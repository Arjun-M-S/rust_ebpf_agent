//! The collector: the off-box half of the tamper-evident log.
//!
//! Everything the agent cannot do for itself happens here, and it all comes
//! down to one property -- this process runs somewhere the monitored host's
//! root does not control.
//!
//!   NOW-3 / STO-4  remembers the high-water `seq` per host, which is the only
//!                  way tail truncation is ever detectable. A chain with its
//!                  last 200 records removed verifies perfectly on the host.
//!   NOW-7          stamps its own receipt time. The agent's timestamp is
//!                  attacker-influenced the moment root is held; this one is not.
//!   NOW-8          holds the escrowed K0. Wiping the WAL and restarting mints
//!                  a new key, and records sealed under it fail here. That
//!                  failure is the detection.
//!   SUP-2          pins the agent's build id at enrollment, so a heartbeating
//!                  stub that reports "all healthy" is caught.
//!   PRX-1 / PRX-2  the proxy is not trusted. It never sees K0, cannot forge a
//!                  record, and cannot usefully replay one (seq must advance).
//!                  What it CAN do is drop batches, which is why silence
//!                  detection below is not optional.
//!
//! PANIC POLICY: the workspace builds release with panic = "abort", so any
//! panic in a request path takes the whole collector down and blinds every
//! enrolled host at once. Treat that as the primary availability risk. Nothing
//! in the ingest path may unwrap, expect, index or slice on request-derived
//! data. The one `expect` reached from here lives in record.rs on HMAC key
//! length, which is infallible for every key length.

mod dashboard;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use edr_record::{derive_epoch_key, evolve_key, parse_key, verify_record, AgentLog, GENESIS_MAC};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Ceiling on how many epochs of key evolution this collector will compute for
/// one record. Epochs are 60s, so this is roughly two years of continuous agent
/// uptime -- far past anything real, and far short of the 2^64 an attacker can
/// put in the `epoch` field of an unverified record. Without it, one POST spins
/// SHA-256 forever inside the handler while holding the lock every other host
/// needs, which is a cheaper way to blind the fleet than forging anything.
const MAX_EPOCH_WALK: u64 = 1_051_200;

#[derive(Parser)]
#[command(name = "edr-collector", about = "Off-box verifier and store for sealed EDR logs")]
struct Cli {
    #[arg(long, default_value = "/var/lib/edr-collector")]
    data_dir: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the ingest server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        /// Seconds without a batch before a host is reported silent.
        #[arg(long, default_value_t = 300)]
        silence_secs: i64,
        /// Where to serve the read-only dashboard. Deliberately a SEPARATE
        /// socket from --listen: the ingest port must be reachable by the
        /// proxy, and the proxy is not trusted. Sharing one port would let it
        /// read every alert on every host. Pass "off" to disable.
        #[arg(long, default_value = "127.0.0.1:8081")]
        dashboard_listen: String,
    },
    /// Register a host and the K0 escrowed for it.
    ///
    /// K0 is entered here by the operator, out of band. The agent never
    /// transmits it: if it did, a TLS-terminating proxy would see the key and
    /// the whole forward-secrecy argument would collapse (PRX-1).
    Enroll {
        #[arg(long)]
        host: String,
        /// 64 hex characters, printed once by the agent on first start.
        #[arg(long)]
        key: String,
        /// Build identity of the agent binary, e.g. sha256 of the executable.
        #[arg(long)]
        build_id: Option<String>,
        /// Replace an existing enrollment. Refuses without this, because a
        /// silent re-key is exactly what NOW-8 is about.
        #[arg(long)]
        force: bool,
    },
    /// Re-verify a host's entire stored chain from K0.
    Verify {
        #[arg(long)]
        host: String,
    },
    /// Print per-host state.
    Status,
}

// ---------------------------------------------------------
// Storage
// ---------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct Enrollment {
    k0: String,
    build_id: Option<String>,
    enrolled_at: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct HostState {
    high_seq: u64,
    high_epoch: u64,
    last_mac: String,
    last_seen: Option<String>,
    /// Incremented on every chain discontinuity. Never reset.
    breaks: u64,
    /// Which chain segment we are in. Starts at 0, increments on each break,
    /// and is stamped on every stored record so a reader can see which side of
    /// a discontinuity a record fell on.
    segment: u64,
    total_records: u64,
    /// Set while a silence alert is outstanding, so one outage produces one
    /// alert rather than one per check.
    silent: bool,
    /// Last build id this host reported. Kept so a mismatch is recorded once
    /// per change rather than once per batch, which would flood the store and
    /// bury the event it is meant to surface.
    #[serde(default)]
    last_build: Option<String>,
}

/// Stored form. The sealed record is kept byte-identical inside `record` so it
/// still verifies; everything the collector knows goes alongside it.
#[derive(Serialize)]
struct StoredRecord<'a> {
    received_at: String,
    segment: u64,
    verified: bool,
    record: &'a AgentLog,
}

struct HostKeys {
    k0: [u8; 32],
    cached_epoch: u64,
    cached_key: [u8; 32],
}

impl HostKeys {
    fn new(k0: [u8; 32]) -> Self {
        Self {
            k0,
            cached_epoch: 0,
            cached_key: k0,
        }
    }

    /// K_epoch, walking forward from the cache where possible.
    ///
    /// Epochs advance once a minute, so in steady state this is zero or one
    /// SHA256 per batch. Deriving from K0 every time would be one hash per
    /// minute of host uptime per record, which is the kind of thing that looks
    /// fine in testing and melts a year later.
    ///
    /// Returns None for an epoch too far out to be worth deriving. The epoch
    /// arrives inside an unverified record, so it has to be bounded before it
    /// is used as a loop count -- see MAX_EPOCH_WALK.
    fn key_for(&mut self, epoch: u64) -> Option<[u8; 32]> {
        if epoch >= self.cached_epoch {
            if epoch - self.cached_epoch > MAX_EPOCH_WALK {
                return None;
            }
            let mut key = self.cached_key;
            for _ in self.cached_epoch..epoch {
                key = evolve_key(&key);
            }
            self.cached_epoch = epoch;
            self.cached_key = key;
            Some(key)
        } else {
            // Out of order, which should not happen. Recompute rather than
            // trust the cache. Reachable with a genuine record after a forged
            // one pushed the cache forward, so it needs the same bound.
            if epoch > MAX_EPOCH_WALK {
                return None;
            }
            Some(derive_epoch_key(&self.k0, epoch))
        }
    }
}

struct Host {
    enrollment: Enrollment,
    keys: HostKeys,
    state: HostState,
}

struct App {
    data_dir: PathBuf,
    // ponytail: one lock over all hosts. Fine for tens of hosts at a batch
    // every few seconds; split per-host if a fleet ever makes it contend.
    hosts: Mutex<HashMap<String, Host>>,
}

fn enroll_path(dir: &Path, host: &str) -> PathBuf {
    dir.join("hosts").join(format!("{}.enroll.json", host))
}

fn state_path(dir: &Path, host: &str) -> PathBuf {
    dir.join("hosts").join(format!("{}.state.json", host))
}

fn events_path(dir: &Path, host: &str) -> PathBuf {
    dir.join("events").join(format!("{}.ndjson", host))
}

/// Host ids become filenames, so anything that could climb out of the data
/// directory is rejected before it is used as one.
fn valid_host_id(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        && !host.starts_with('.')
        && !host.contains("..")
}

fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn load_state(dir: &Path, host: &str) -> HostState {
    std::fs::read_to_string(state_path(dir, host))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| HostState {
            last_mac: GENESIS_MAC.to_string(),
            ..Default::default()
        })
}

fn save_state(dir: &Path, host: &str, state: &HostState) {
    match serde_json::to_string_pretty(state) {
        Ok(s) => {
            if let Err(e) = write_atomic(&state_path(dir, host), &s) {
                eprintln!("CRITICAL: could not persist state for {}: {}", host, e);
            }
        }
        Err(e) => eprintln!("CRITICAL: could not serialize state for {}: {}", host, e),
    }
}

fn load_enrollment(dir: &Path, host: &str) -> Option<Enrollment> {
    std::fs::read_to_string(enroll_path(dir, host))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

// ---------------------------------------------------------
// Ingest
// ---------------------------------------------------------

/// What went wrong with a record, if anything.
enum Reject {
    Gap { expected: u64, got: u64 },
    EpochWentBackwards { high: u64, got: u64 },
    ImplausibleEpoch { got: u64 },
    BrokenLink,
    BadMac,
}

impl Reject {
    fn describe(&self) -> String {
        match self {
            Reject::Gap { expected, got } => format!(
                "sequence gap: expected seq={}, received seq={}. {} record(s) are missing.",
                expected,
                got,
                got.saturating_sub(*expected)
            ),
            Reject::EpochWentBackwards { high, got } => format!(
                "epoch went backwards: highest seen {}, received {}. Key evolution is \
                 one-way, so this record could not have been sealed after the last one.",
                high, got
            ),
            Reject::ImplausibleEpoch { got } => format!(
                "epoch {} is beyond the {} this collector will derive keys for (~{} years \
                 of agent uptime). Deriving it would mean that many SHA-256 rounds, so the \
                 record is refused rather than computed.",
                got,
                MAX_EPOCH_WALK,
                MAX_EPOCH_WALK / (365 * 24 * 60)
            ),
            Reject::BrokenLink => {
                "prev_hash does not match the last record stored. The chain was cut.".to_string()
            }
            Reject::BadMac => {
                "MAC does not verify under the escrowed K0. The record was forged, altered, \
                 or sealed with a key this collector was not given."
                    .to_string()
            }
        }
    }
}

fn check_record(state: &HostState, keys: &mut HostKeys, rec: &AgentLog) -> Option<Reject> {
    let expected = state.high_seq + 1;
    if rec.seq != expected {
        return Some(Reject::Gap {
            expected,
            got: rec.seq,
        });
    }
    if rec.epoch < state.high_epoch {
        return Some(Reject::EpochWentBackwards {
            high: state.high_epoch,
            got: rec.epoch,
        });
    }
    if rec.prev_hash != state.last_mac {
        return Some(Reject::BrokenLink);
    }
    // Bounded before it is derived. Key derivation walks one SHA-256 per epoch,
    // so an unbounded epoch in an attacker-supplied record is a hang: it spins
    // in the handler while holding the lock every other host needs.
    let Some(key) = keys.key_for(rec.epoch) else {
        return Some(Reject::ImplausibleEpoch { got: rec.epoch });
    };
    if !verify_record(&key, rec) {
        return Some(Reject::BadMac);
    }
    None
}

async fn ingest(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let host = match headers.get("X-EDR-Host").and_then(|v| v.to_str().ok()) {
        Some(h) if valid_host_id(h) => h.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"acked_seq": 0, "error": "missing or invalid X-EDR-Host"})),
            )
        }
    };

    let mut hosts = app.hosts.lock().await;

    // Load on first contact. An unenrolled host is refused: without K0 there is
    // nothing to verify against, and storing unverifiable records under a name
    // an attacker chose would be worse than refusing them.
    if !hosts.contains_key(&host) {
        let Some(enrollment) = load_enrollment(&app.data_dir, &host) else {
            eprintln!("WARNING: rejected batch from unenrolled host {:?}", host);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"acked_seq": 0, "error": "host is not enrolled"})),
            );
        };
        let Ok(k0) = parse_key(&enrollment.k0) else {
            eprintln!("CRITICAL: enrollment for {} has an unusable K0", host);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"acked_seq": 0, "error": "enrollment is corrupt"})),
            );
        };
        let state = load_state(&app.data_dir, &host);
        hosts.insert(
            host.clone(),
            Host {
                enrollment,
                keys: HostKeys::new(k0),
                state,
            },
        );
    }

    let Some(entry) = hosts.get_mut(&host) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"acked_seq": 0, "error": "host vanished from registry"})),
        );
    };

    let now: DateTime<Utc> = Utc::now();
    let mut out = String::with_capacity(body.len() + 256);
    let mut accepted = 0u64;
    let mut first_error: Option<String> = None;

    // SUP-2: the agent reports the identity of the binary that is running. A
    // stub that heartbeats and reports nothing is otherwise indistinguishable
    // from a quiet host. Recorded rather than refused: refusing would blind us
    // to the records the impostor is still sending, which are evidence.
    let reported_build = headers
        .get("X-EDR-Build")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let build_changed = entry.state.last_build.as_deref() != Some(reported_build);
    if !reported_build.is_empty() && build_changed {
        entry.state.last_build = Some(reported_build.to_string());
    }
    if let Some(expected) = entry.enrollment.build_id.as_deref() {
        if !reported_build.is_empty() && reported_build != expected && build_changed {
            eprintln!(
                "CRITICAL: host {} is running a binary that was not enrolled. \
                 Expected build {}, got {}. The agent executable was replaced.",
                host, expected, reported_build
            );
            let marker = json!({
                "received_at": now.to_rfc3339(),
                "segment": entry.state.segment,
                "collector_event": "BUILD_MISMATCH",
                "expected_build": expected,
                "reported_build": reported_build,
                "detail": "the agent binary does not match the one enrolled for this host",
            });
            if let Ok(s) = serde_json::to_string(&marker) {
                out.push_str(&s);
                out.push('\n');
            }
            if first_error.is_none() {
                first_error = Some("agent binary does not match enrollment".to_string());
            }
        }
    }

    // Snapshot before touching anything. If the append below fails we have to
    // put the in-memory state back exactly as it was: it advanced per record,
    // and leaving it advanced would make the agent's retry hit the "already
    // seen" branch and drop the batch permanently over a transient disk error.
    let pre_batch = entry.state.clone();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let rec: AgentLog = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(format!("unparseable record: {}", e));
                }
                continue;
            }
        };

        // Idempotent replay. A retried batch after a lost ack is normal, and a
        // deliberate replay by the proxy is a no-op for the same reason.
        if rec.seq <= entry.state.high_seq {
            continue;
        }

        let verdict = check_record(&entry.state, &mut entry.keys, &rec);

        if let Some(reject) = &verdict {
            let detail = reject.describe();
            eprintln!(
                "CRITICAL: chain break for host {} at seq {}: {}",
                host, rec.seq, detail
            );
            entry.state.breaks += 1;
            entry.state.segment += 1;
            if first_error.is_none() {
                first_error = Some(detail.clone());
            }

            // The break itself is evidence and is stored before the record that
            // triggered it. This is the artifact an investigator reads.
            let marker = json!({
                "received_at": now.to_rfc3339(),
                "segment": entry.state.segment,
                "collector_event": "CHAIN_BREAK",
                "at_seq": rec.seq,
                "expected_seq": entry.state.high_seq + 1,
                "expected_prev_hash": entry.state.last_mac,
                "detail": detail,
            });
            if let Ok(s) = serde_json::to_string(&marker) {
                out.push_str(&s);
                out.push('\n');
            }
        }

        // Stored either way, flagged with whether it verified. Refusing to
        // store a suspect record would delete the evidence; re-anchoring to it
        // is what lets genuine records after the break keep flowing instead of
        // every later batch failing against a position the host has left behind.
        let stored = StoredRecord {
            received_at: now.to_rfc3339(),
            segment: entry.state.segment,
            verified: verdict.is_none(),
            record: &rec,
        };
        if let Ok(s) = serde_json::to_string(&stored) {
            out.push_str(&s);
            out.push('\n');
        }

        entry.state.high_seq = rec.seq;
        entry.state.high_epoch = entry.state.high_epoch.max(rec.epoch);
        entry.state.last_mac = rec.hash.clone();
        entry.state.total_records += 1;
        accepted += 1;
    }

    if !out.is_empty() {
        let path = events_path(&app.data_dir, &host);
        let append = || -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            f.write_all(out.as_bytes())?;
            f.sync_all()
        };
        if let Err(e) = append() {
            // Do NOT ack what was not stored. The agent keeps it in the WAL and
            // retries; acking here would delete the only remaining copy.
            // seq is not dense -- a gap means high_seq - accepted is not the
            // pre-batch position and could ack past records that were never
            // written -- so roll back to the snapshot and ack that.
            eprintln!("CRITICAL: could not append events for {}: {}", host, e);
            let acked = pre_batch.high_seq;
            entry.state = pre_batch;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"acked_seq": acked, "error": "storage write failed"})),
            );
        }
    }

    entry.state.last_seen = Some(now.to_rfc3339());
    if entry.state.silent {
        eprintln!("host {} is reporting again", host);
        entry.state.silent = false;
    }

    let acked = entry.state.high_seq;
    let state_copy = entry.state.clone();
    drop(hosts);

    save_state(&app.data_dir, &host, &state_copy);

    match first_error {
        Some(err) => (
            StatusCode::CONFLICT,
            Json(json!({"acked_seq": acked, "error": err})),
        ),
        None => (StatusCode::OK, Json(json!({"acked_seq": acked}))),
    }
}

async fn status(State(app): State<Arc<App>>) -> impl IntoResponse {
    let hosts = app.hosts.lock().await;
    let summary: Vec<_> = hosts
        .iter()
        .map(|(name, h)| {
            json!({
                "host": name,
                "high_seq": h.state.high_seq,
                "epoch": h.state.high_epoch,
                "records": h.state.total_records,
                "breaks": h.state.breaks,
                "segment": h.state.segment,
                "last_seen": h.state.last_seen,
                "silent": h.state.silent,
            })
        })
        .collect();
    Json(json!({"hosts": summary}))
}

async fn health() -> &'static str {
    "ok\n"
}

// ---------------------------------------------------------
// Silence detection
// ---------------------------------------------------------

/// PRX-5: an agent that stops reporting looks exactly like an agent with
/// nothing to report. Silence is the loudest signal this system has, and it is
/// only audible from here -- a host that has been taken over will not tell you
/// it went quiet.
///
/// Also covers the proxy dropping batches (PRX-2), which is the one attack a
/// non-trusted proxy can still mount against a chain it cannot forge.
async fn watch_for_silence(app: Arc<App>, silence_secs: i64) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    tick.tick().await;
    loop {
        tick.tick().await;
        let now = Utc::now();
        let mut newly_silent = Vec::new();

        {
            let mut hosts = app.hosts.lock().await;
            for (name, h) in hosts.iter_mut() {
                if h.state.silent {
                    continue;
                }
                let Some(seen) = h.state.last_seen.as_deref() else {
                    continue;
                };
                let Ok(seen) = DateTime::parse_from_rfc3339(seen) else {
                    continue;
                };
                let quiet_for = now.signed_duration_since(seen.with_timezone(&Utc));
                if quiet_for.num_seconds() > silence_secs {
                    h.state.silent = true;
                    newly_silent.push((name.clone(), quiet_for.num_seconds(), h.state.clone()));
                }
            }
        }

        for (name, secs, state) in newly_silent {
            eprintln!(
                "CRITICAL: host {} has been silent for {}s (threshold {}s). Last record was \
                 seq={}. The agent is stopped, the host is offline, or something between \
                 here and it is dropping batches.",
                name, secs, silence_secs, state.high_seq
            );
            save_state(&app.data_dir, &name, &state);
        }
    }
}

// ---------------------------------------------------------
// Subcommands
// ---------------------------------------------------------

fn cmd_enroll(
    dir: &Path,
    host: &str,
    key: &str,
    build_id: Option<String>,
    force: bool,
) -> Result<(), anyhow::Error> {
    if !valid_host_id(host) {
        anyhow::bail!("host id may only contain letters, digits, '-', '.', '_'");
    }
    parse_key(key).map_err(|e| anyhow::anyhow!("K0 is unusable: {}", e))?;

    let path = enroll_path(dir, host);
    if path.exists() && !force {
        anyhow::bail!(
            "{} is already enrolled. Re-enrolling under a new K0 is exactly what a \
             wiped-and-restarted agent looks like (NOW-8), so it is refused by default. \
             If this is a genuine rebuild, pass --force; the existing chain will stop \
             verifying and that break stays in the record.",
            host
        );
    }

    let enrollment = Enrollment {
        k0: key.trim().to_string(),
        build_id,
        enrolled_at: Utc::now().to_rfc3339(),
    };
    write_atomic(&path, &serde_json::to_string_pretty(&enrollment)?)?;

    // A forced re-enrollment resets chain position, otherwise every record
    // from the new agent fails against the old high-water mark forever.
    if force {
        let fresh = HostState {
            last_mac: GENESIS_MAC.to_string(),
            ..Default::default()
        };
        save_state(dir, host, &fresh);
        eprintln!(
            "WARNING: chain position for {} was reset. Records stored before now remain \
             on disk but belong to the previous chain.",
            host
        );
    }

    println!("Enrolled {} (K0 recorded, build_id {:?})", host, enrollment.build_id);
    Ok(())
}

/// Re-verify everything stored for a host from K0.
///
/// The ingest path already verified each record as it arrived, so this is for
/// the case that actually matters: proving the COLLECTOR's own store has not
/// been altered since. It re-derives every key from K0 and re-checks every MAC.
fn cmd_verify(dir: &Path, host: &str) -> Result<(), anyhow::Error> {
    let Some(enrollment) = load_enrollment(dir, host) else {
        anyhow::bail!("{} is not enrolled", host);
    };
    let k0 = parse_key(&enrollment.k0).map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut keys = HostKeys::new(k0);

    let path = events_path(dir, host);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {:?}: {}", path, e))?;

    let mut checked = 0u64;
    let mut failed = 0u64;
    let mut breaks = 0u64;
    let mut expected_seq: Option<u64> = None;
    let mut last_mac = GENESIS_MAC.to_string();

    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                println!("line {}: unparseable: {}", lineno + 1, e);
                failed += 1;
                continue;
            }
        };

        if value.get("collector_event").is_some() {
            breaks += 1;
            println!(
                "line {}: CHAIN BREAK recorded at ingest: {}",
                lineno + 1,
                value.get("detail").and_then(|d| d.as_str()).unwrap_or("")
            );
            // A recorded break re-anchors, same as it did at ingest.
            expected_seq = None;
            continue;
        }

        let Some(rec_value) = value.get("record") else {
            continue;
        };
        let rec: AgentLog = match serde_json::from_value(rec_value.clone()) {
            Ok(r) => r,
            Err(e) => {
                println!("line {}: record does not decode: {}", lineno + 1, e);
                failed += 1;
                continue;
            }
        };

        if let Some(exp) = expected_seq {
            if rec.seq != exp {
                println!(
                    "line {}: SEQUENCE GAP in the collector's own store: expected {}, found {}",
                    lineno + 1,
                    exp,
                    rec.seq
                );
                failed += 1;
            } else if rec.prev_hash != last_mac {
                println!("line {}: BROKEN LINK in the collector's own store", lineno + 1);
                failed += 1;
            }
        }

        match keys.key_for(rec.epoch) {
            Some(key) if verify_record(&key, &rec) => {}
            Some(_) => {
                println!("line {}: MAC FAILS at seq {}", lineno + 1, rec.seq);
                failed += 1;
            }
            None => {
                println!(
                    "line {}: epoch {} at seq {} is beyond MAX_EPOCH_WALK; not verifiable",
                    lineno + 1,
                    rec.epoch,
                    rec.seq
                );
                failed += 1;
            }
        }

        expected_seq = Some(rec.seq + 1);
        last_mac = rec.hash.clone();
        checked += 1;
    }

    println!();
    println!("host          {}", host);
    println!("records       {}", checked);
    println!("chain breaks  {}", breaks);
    println!("failures      {}", failed);
    if failed == 0 && breaks == 0 {
        println!("RESULT        intact");
    } else if failed == 0 {
        println!("RESULT        every stored record verifies, but {} break(s) are recorded.", breaks);
        println!("              Records are missing between segments. Investigate the gaps.");
    } else {
        println!("RESULT        TAMPERED. The collector's own store does not verify.");
    }
    Ok(())
}

fn cmd_status(dir: &Path) -> Result<(), anyhow::Error> {
    let hosts_dir = dir.join("hosts");
    let Ok(entries) = std::fs::read_dir(&hosts_dir) else {
        println!("no hosts enrolled under {:?}", hosts_dir);
        return Ok(());
    };

    println!(
        "{:<24} {:>10} {:>8} {:>7} {:>8}  {}",
        "HOST", "HIGH SEQ", "RECORDS", "BREAKS", "SILENT", "LAST SEEN"
    );
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(host) = name.strip_suffix(".enroll.json") else {
            continue;
        };
        let state = load_state(dir, host);
        println!(
            "{:<24} {:>10} {:>8} {:>7} {:>8}  {}",
            host,
            state.high_seq,
            state.total_records,
            state.breaks,
            state.silent,
            state.last_seen.as_deref().unwrap_or("never")
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.cmd {
        Command::Enroll {
            host,
            key,
            build_id,
            force,
        } => cmd_enroll(&cli.data_dir, &host, &key, build_id, force),

        Command::Verify { host } => cmd_verify(&cli.data_dir, &host),

        Command::Status => cmd_status(&cli.data_dir),

        Command::Serve {
            listen,
            silence_secs,
            dashboard_listen,
        } => {
            std::fs::create_dir_all(cli.data_dir.join("hosts"))?;
            std::fs::create_dir_all(cli.data_dir.join("events"))?;

            let app = Arc::new(App {
                data_dir: cli.data_dir.clone(),
                hosts: Mutex::new(HashMap::new()),
            });

            // Warm the registry so `status` and silence detection see hosts
            // that have not reported since this process started.
            if let Ok(entries) = std::fs::read_dir(cli.data_dir.join("hosts")) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let Some(host) = name.strip_suffix(".enroll.json") else {
                        continue;
                    };
                    let Some(enrollment) = load_enrollment(&cli.data_dir, host) else {
                        continue;
                    };
                    let Ok(k0) = parse_key(&enrollment.k0) else {
                        eprintln!("CRITICAL: enrollment for {} has an unusable K0", host);
                        continue;
                    };
                    let state = load_state(&cli.data_dir, host);
                    app.hosts.lock().await.insert(
                        host.to_string(),
                        Host {
                            enrollment,
                            keys: HostKeys::new(k0),
                            state,
                        },
                    );
                }
            }

            let enrolled = app.hosts.lock().await.len();

            tokio::spawn(watch_for_silence(Arc::clone(&app), silence_secs));

            // Dashboard on its own socket. Bound before the ingest listener so
            // a typo'd bind address fails fast instead of after agents have
            // started delivering.
            if dashboard_listen != "off" {
                let dash_listener = tokio::net::TcpListener::bind(&dashboard_listen).await?;
                let dash_router = dashboard::routes(Arc::clone(&app));
                eprintln!(
                    "dashboard on http://{} -- read-only, no authentication. Keep it bound to \
                     localhost or the analyst network and put an authenticating reverse proxy \
                     in front. It must NEVER be reachable from the agent-facing side.",
                    dashboard_listen
                );
                tokio::spawn(async move {
                    let served = axum::serve(dash_listener, dash_router)
                        .with_graceful_shutdown(async {
                            let _ = tokio::signal::ctrl_c().await;
                        })
                        .await;
                    if let Err(e) = served {
                        eprintln!("CRITICAL: dashboard server stopped: {}", e);
                    }
                });
            }

            let router = Router::new()
                .route("/v1/ingest", post(ingest))
                .route("/v1/status", get(status))
                .route("/healthz", get(health))
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
                .with_state(Arc::clone(&app));

            let listener = tokio::net::TcpListener::bind(&listen).await?;
            eprintln!(
                "edr-collector listening on {} | {} host(s) enrolled | data {:?}",
                listen, enrolled, cli.data_dir
            );
            eprintln!(
                "NOTE: plain HTTP. Terminate TLS in front of this and bind it to localhost."
            );

            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                    eprintln!("shutting down");
                })
                .await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_record::record_mac;

    fn seal(key: &[u8; 32], seq: u64, epoch: u64, prev: &str) -> AgentLog {
        let mut log = AgentLog {
            seq,
            epoch,
            timestamp: "2026-08-16T10:00:00+00:00".to_string(),
            severity: "INFO".to_string(),
            event_type: "PROCESS_EXEC".to_string(),
            process_name: "bash".to_string(),
            prev_hash: prev.to_string(),
            ..Default::default()
        };
        log.hash = record_mac(key, &log);
        log
    }

    fn fresh_state() -> HostState {
        HostState {
            last_mac: GENESIS_MAC.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_chain_is_accepted() {
        let k0 = [3u8; 32];
        let mut keys = HostKeys::new(k0);
        let mut state = fresh_state();

        let mut prev = GENESIS_MAC.to_string();
        for seq in 1..=5 {
            let rec = seal(&k0, seq, 0, &prev);
            assert!(check_record(&state, &mut keys, &rec).is_none(), "seq {}", seq);
            state.high_seq = rec.seq;
            state.last_mac = rec.hash.clone();
            prev = rec.hash;
        }
        assert_eq!(state.high_seq, 5);
    }

    /// The finding this whole component exists for. Truncation is invisible on
    /// the host; here it is a gap.
    #[test]
    fn truncation_shows_up_as_a_gap() {
        let k0 = [3u8; 32];
        let mut keys = HostKeys::new(k0);
        let mut state = fresh_state();

        let r1 = seal(&k0, 1, 0, GENESIS_MAC);
        assert!(check_record(&state, &mut keys, &r1).is_none());
        state.high_seq = 1;
        state.last_mac = r1.hash.clone();

        // Records 2 and 3 deleted; 4 arrives with a valid MAC of its own.
        let r4 = seal(&k0, 4, 0, &r1.hash);
        match check_record(&state, &mut keys, &r4) {
            Some(Reject::Gap { expected, got }) => {
                assert_eq!(expected, 2);
                assert_eq!(got, 4);
            }
            _ => panic!("a sequence gap must be rejected"),
        }
    }

    #[test]
    fn a_chain_under_a_different_k0_is_rejected() {
        let real = [3u8; 32];
        let forged = [9u8; 32];
        let mut keys = HostKeys::new(real);
        let state = fresh_state();

        let rec = seal(&forged, 1, 0, GENESIS_MAC);
        assert!(matches!(
            check_record(&state, &mut keys, &rec),
            Some(Reject::BadMac)
        ));
    }

    #[test]
    fn altered_field_fails_the_mac() {
        let k0 = [3u8; 32];
        let mut keys = HostKeys::new(k0);
        let state = fresh_state();

        let mut rec = seal(&k0, 1, 0, GENESIS_MAC);
        rec.process_name = "sh".to_string();
        assert!(matches!(
            check_record(&state, &mut keys, &rec),
            Some(Reject::BadMac)
        ));
    }

    #[test]
    fn broken_link_is_caught_even_with_a_valid_mac() {
        let k0 = [3u8; 32];
        let mut keys = HostKeys::new(k0);
        let mut state = fresh_state();

        let r1 = seal(&k0, 1, 0, GENESIS_MAC);
        state.high_seq = 1;
        state.last_mac = r1.hash.clone();

        // Correctly sealed, but points at the wrong predecessor.
        let r2 = seal(&k0, 2, 0, &"ff".repeat(32));
        assert!(matches!(
            check_record(&state, &mut keys, &r2),
            Some(Reject::BrokenLink)
        ));
    }

    #[test]
    fn epoch_cannot_go_backwards() {
        let k0 = [3u8; 32];
        let mut keys = HostKeys::new(k0);
        let mut state = fresh_state();
        state.high_seq = 1;
        state.high_epoch = 5;
        state.last_mac = "aa".repeat(32);

        let k5 = derive_epoch_key(&k0, 3);
        let rec = seal(&k5, 2, 3, &state.last_mac);
        assert!(matches!(
            check_record(&state, &mut keys, &rec),
            Some(Reject::EpochWentBackwards { .. })
        ));
    }

    #[test]
    fn key_cache_matches_direct_derivation() {
        let k0 = [3u8; 32];
        let mut keys = HostKeys::new(k0);
        assert_eq!(keys.key_for(0), Some(k0));
        assert_eq!(keys.key_for(3), Some(derive_epoch_key(&k0, 3)));
        assert_eq!(keys.key_for(7), Some(derive_epoch_key(&k0, 7)));
        // Backwards must not read a stale cache.
        assert_eq!(keys.key_for(2), Some(derive_epoch_key(&k0, 2)));
    }

    /// A record carrying epoch=u64::MAX must be refused, not derived. Deriving
    /// it hangs the handler with the global lock held, which blinds every host.
    #[test]
    fn absurd_epoch_is_refused_instead_of_derived() {
        let mut keys = HostKeys::new([4u8; 32]);
        assert_eq!(keys.key_for(u64::MAX), None);
        assert_eq!(keys.key_for(MAX_EPOCH_WALK + 1), None);
        // The bound must not have broken ordinary derivation.
        assert!(keys.key_for(5).is_some());
    }

    #[test]
    fn host_ids_that_escape_the_data_dir_are_refused() {
        assert!(valid_host_id("web-01.prod"));
        assert!(!valid_host_id("../../etc/passwd"));
        assert!(!valid_host_id("a/b"));
        assert!(!valid_host_id(".hidden"));
        assert!(!valid_host_id(""));
        assert!(!valid_host_id("a..b"));
    }
}
