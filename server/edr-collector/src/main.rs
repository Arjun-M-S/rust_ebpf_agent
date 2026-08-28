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
use edr_record::{
    derive_epoch_key, evolve_key, merkle, parse_key, verify_record, AgentLog, GENESIS_MAC,
};
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
        /// Ingest requests admitted at once. This bounds worst-case ingest
        /// memory at roughly max_concurrent_ingest * 16 MB (the body limit),
        /// so the default is ~512 MB. Excess requests get 503 + Retry-After,
        /// never a 4xx: the shipper keeps them in its WAL and retries, so
        /// shedding here costs latency and nothing else.
        #[arg(long, default_value_t = 32)]
        max_concurrent_ingest: usize,
        /// Seal a Merkle batch per accepted POST. Off stores records exactly as
        /// before but commits to nothing, so proofs cannot be issued for
        /// anything ingested while it was off.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        merkle: bool,
        /// Seal a fleet-wide root at least this often, when anything is
        /// pending. Trades gas cost against worst-case proof latency: a record
        /// is not independently timestamped until the root covering it is
        /// anchored.
        #[arg(long, default_value_t = 600)]
        root_interval_secs: u64,
        /// ...or as soon as this many batches are waiting, whichever comes
        /// first. Bounds how much is riding on a single unsealed queue.
        #[arg(long, default_value_t = 256)]
        root_max_batches: usize,
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
    /// Recompute every commitment from the stored bytes and report drift.
    ///
    /// This is the one an auditor runs. It re-derives every batch chainhash
    /// from the actual bytes in `events/{host}.ndjson` and every root from the
    /// chainhashes those roots name, and needs no K0 to do it.
    MerkleAudit {
        /// Audit one host instead of every host that has batches.
        #[arg(long)]
        host: Option<String>,
    },
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
    /// Next batch_id for this host. Dense, starts at 0.
    ///
    /// This and the two below are #[serde(default)] so a state file written
    /// before Merkle batching existed still loads and simply starts at batch 0.
    #[serde(default)]
    batches: u64,
    /// Previous batch's chainhash, GENESIS_MAC when there is none. Chains
    /// batches the way prev_hash chains records, so deleting a whole batch line
    /// is visible without reaching for the on-chain root.
    #[serde(default)]
    last_chainhash: String,
    /// Highest seq covered by a sealed batch.
    #[serde(default)]
    last_committed_seq: u64,
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

// ---------------------------------------------------------
// Merkle batching (server.md 2.4 / 2.5)
// ---------------------------------------------------------

/// One line of `batches/{host}.ndjson`: the commitment to exactly one accepted
/// POST.
///
/// Strictly append-only, like the events file. Nothing here is ever patched in
/// place -- notably there is no `root_id` field, because the batch -> root
/// mapping lives in the root line instead. A file that is only ever appended to
/// is one whose tampering shows up in its size and its chain links alone.
#[derive(Serialize, Deserialize)]
struct BatchLine {
    v: u32,
    batch_id: u64,
    host: String,
    sealed_at: String,
    chainhash: String,
    prev_chainhash: String,
    count: u32,
    /// Records only. A markers-only batch has no seq, and both are 0.
    seq_lo: u64,
    seq_hi: u64,
    segment: u64,
    /// The exact byte range this batch appended to `events/{host}.ndjson`.
    ///
    /// Committing to bytes rather than to sequence numbers is what makes the
    /// design immune to duplicate lines: if a retry appends the same records
    /// twice, the second copy is simply bytes no batch names.
    byte_start: u64,
    byte_end: u64,
    /// Every leaf hash in order. ~64 hex bytes per ~370-byte record is about
    /// 17% storage overhead, and it buys proof generation with two file reads
    /// and no re-hashing of the events file.
    ///
    /// ponytail: stored rather than recomputed. Drop it and re-derive from the
    /// byte range if the overhead ever matters more than proof latency.
    leaves: Vec<String>,
}

/// Which of one host's batches a root covers, and their chainhashes.
///
/// The chainhashes are stored so proof generation never has to reach back into
/// a host's files -- which is also what lets the root sealer run without ever
/// taking a host lock.
#[derive(Serialize, Deserialize, Clone)]
struct RootCover {
    host: String,
    batch_lo: u64,
    batch_hi: u64,
    chainhashes: Vec<String>,
}

/// One line of `roots.ndjson`: the periodic, FLEET-WIDE commitment over every
/// batch sealed since the last root.
///
/// Fleet-wide rather than per host on purpose. One root per interval is one
/// blockchain transaction per interval no matter how many hosts are enrolled;
/// per-host roots would make anchoring cost scale with fleet size, which looks
/// fine with one host and is unaffordable with two hundred. Cross-host leaf
/// substitution is prevented instead by binding the host id into the level-2
/// leaf preimage (`merkle::batch_leaf`).
#[derive(Serialize, Deserialize)]
struct RootLine {
    v: u32,
    root_id: u64,
    sealed_at: String,
    root: String,
    /// Previous root, GENESIS_MAC for root_id 0. Deleting a whole root line is
    /// visible from this alone, without consulting the chain.
    prev_root: String,
    leaf_count: u64,
    /// Hosts ascending, batches ascending within a host. THIS IS THE ORDER THE
    /// LEVEL-2 LEAF VECTOR IS BUILT IN and it is part of the format: a verifier
    /// that sorts differently computes a different root and every proof fails.
    covers: Vec<RootCover>,
}

/// What the in-memory index keeps per batch. Deliberately not the leaves --
/// only where to find them.
///
/// Populated here rather than in the step that reads it, because filling it is
/// an ingest-path concern: the entry has to be pushed under the same lock that
/// appended the batch. `merkle-audit` (step 6) and the retrieval API (step 8)
/// are the readers.
#[allow(dead_code)]
#[derive(Clone)]
struct BatchIndexEntry {
    batch_id: u64,
    seq_lo: u64,
    seq_hi: u64,
    segment: u64,
    byte_start: u64,
    byte_end: u64,
    count: u32,
    sealed_at: String,
    /// Byte offset of this line within `batches/{host}.ndjson`, so serving a
    /// proof reads one line instead of the whole file.
    line_offset: u64,
}

/// Where one sealed root lives and what it covers. The `covers` ranges are the
/// batch -> root mapping; nothing is ever written back into a batch line.
#[allow(dead_code)]
#[derive(Clone)]
struct RootIndexEntry {
    root_id: u64,
    sealed_at: String,
    root: String,
    /// Byte offset of this line within `roots.ndjson`.
    line_offset: u64,
    /// (host, batch_lo, batch_hi).
    covers: Vec<(String, u64, u64)>,
}

/// A batch that has been sealed but is not yet in a root.
///
/// The chainhash is cached here at ingest precisely so the root sealer needs no
/// host lock and no file read to build a root. That is what keeps the lock
/// graph acyclic (see LOCK ORDER).
#[derive(Clone)]
struct PendingBatch {
    host: String,
    batch_id: u64,
    chainhash: [u8; 32],
}

/// Cross-host Merkle state. The one thing here that is genuinely shared, and so
/// the one place many agents contend.
///
/// ponytail: rebuilt by a full scan at startup. At 500 records per batch, a
/// year of one busy host is ~60k lines -- fine to walk. Add a checkpoint file
/// if boot time ever becomes noticeable.
struct MerkleIndex {
    /// Per host, ordered by batch_id, which is also insertion order.
    batches: HashMap<String, Vec<BatchIndexEntry>>,
    /// Ordered by root_id.
    roots: Vec<RootIndexEntry>,
    /// Sealed but not yet rooted, in the order the batches were sealed. Append
    /// only at the tail; the sealer removes a prefix. That is what makes
    /// "remove exactly the ones I sealed" a `drain(..n)` even though ingest
    /// keeps pushing while the sealer has the lock released.
    pending: Vec<PendingBatch>,
    next_root_id: u64,
    /// Previous root's hash, GENESIS_MAC when none has been sealed.
    last_root: String,
    /// When the last root was sealed, for the interval trigger. Starts at
    /// process start, so a restart does not immediately seal a one-batch root.
    last_seal: std::time::Instant,
}

impl Default for MerkleIndex {
    fn default() -> Self {
        MerkleIndex {
            batches: HashMap::new(),
            roots: Vec::new(),
            pending: Vec::new(),
            next_root_id: 0,
            last_root: GENESIS_MAC.to_string(),
            last_seal: std::time::Instant::now(),
        }
    }
}

impl MerkleIndex {
    /// Single sequential pass over `roots.ndjson` and every
    /// `batches/*.ndjson` at startup.
    ///
    /// Roots are read first because a batch is pending exactly when no root
    /// covers it. Roots seal a host's batches in ascending order, so "covered"
    /// is always a prefix per host and the highest covered batch_id is all that
    /// needs remembering.
    fn load(dir: &Path) -> Self {
        let mut index = MerkleIndex::default();
        let mut covered: HashMap<String, u64> = HashMap::new();

        if let Ok(raw) = std::fs::read_to_string(roots_path(dir)) {
            let mut offset = 0u64;
            for line in raw.split_inclusive('\n') {
                let start = offset;
                offset = offset.saturating_add(line.len() as u64);
                let Ok(r) = serde_json::from_str::<RootLine>(line.trim_end()) else {
                    if !line.trim().is_empty() {
                        eprintln!("CRITICAL: unparseable root line at byte {}", start);
                    }
                    continue;
                };
                for c in &r.covers {
                    let slot = covered.entry(c.host.clone()).or_insert(c.batch_hi);
                    *slot = (*slot).max(c.batch_hi);
                }
                index.next_root_id = index.next_root_id.max(r.root_id.saturating_add(1));
                index.last_root = r.root.clone();
                index.roots.push(RootIndexEntry {
                    root_id: r.root_id,
                    sealed_at: r.sealed_at,
                    root: r.root,
                    line_offset: start,
                    covers: r
                        .covers
                        .into_iter()
                        .map(|c| (c.host, c.batch_lo, c.batch_hi))
                        .collect(),
                });
            }
        }

        let Ok(entries) = std::fs::read_dir(dir.join("batches")) else {
            return index;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(host) = name.strip_suffix(".ndjson") else {
                continue;
            };
            let Ok(raw) = std::fs::read_to_string(entry.path()) else {
                eprintln!("CRITICAL: could not read batch index for {}", host);
                continue;
            };
            let mut offset = 0u64;
            let mut list = Vec::new();
            for line in raw.split_inclusive('\n') {
                let start = offset;
                offset = offset.saturating_add(line.len() as u64);
                let Ok(b) = serde_json::from_str::<BatchLine>(line.trim_end()) else {
                    if !line.trim().is_empty() {
                        eprintln!("CRITICAL: unparseable batch line for {} at byte {}", host, start);
                    }
                    continue;
                };
                let rooted = match covered.get(host) {
                    Some(hi) => b.batch_id <= *hi,
                    None => false,
                };
                if !rooted {
                    match unhex(&b.chainhash) {
                        Some(chainhash) => index.pending.push(PendingBatch {
                            host: host.to_string(),
                            batch_id: b.batch_id,
                            chainhash,
                        }),
                        None => eprintln!(
                            "CRITICAL: batch {} for {} has an unusable chainhash; it cannot be rooted",
                            b.batch_id, host
                        ),
                    }
                }
                list.push(BatchIndexEntry {
                    batch_id: b.batch_id,
                    seq_lo: b.seq_lo,
                    seq_hi: b.seq_hi,
                    segment: b.segment,
                    byte_start: b.byte_start,
                    byte_end: b.byte_end,
                    count: b.count,
                    sealed_at: b.sealed_at,
                    line_offset: start,
                });
            }
            if !list.is_empty() {
                index.batches.insert(host.to_string(), list);
            }
        }
        // read_dir hands hosts back in whatever order the filesystem likes;
        // the sealer sorts again before hashing, but a deterministic pending
        // order keeps the drain-a-prefix invariant easy to reason about.
        index
            .pending
            .sort_by(|a, b| a.host.cmp(&b.host).then(a.batch_id.cmp(&b.batch_id)));
        index
    }
}

/// LOCK ORDER -- exactly one order is legal, and every handler must obey it:
///
///     app.hosts (registry)  ->  Host (per-host)  ->  app.merkle (index)
///
/// Violating it deadlocks the collector, and `panic = "abort"` means a
/// deadlocked collector blinds the whole fleet. The rules that keep the graph
/// acyclic:
///
///   * The registry guard is held only long enough to clone an `Arc`. Never
///     across file I/O, never across a network call, never across `.await` on
///     another lock. A miss drops the guard, loads from disk, then re-acquires.
///   * `ingest`: registry (brief) -> host -> merkle (brief). The host guard IS
///     held across the append `.await`, which is why these are tokio mutexes
///     and not std ones.
///   * Critical sections on `merkle` are pure in-memory work: no file I/O, no
///     hashing of a whole batch, no `.await` on anything but the lock. It is
///     the one lock every host touches, so anything slow held under it
///     reintroduces exactly the fleet-wide serialisation the per-host split
///     removed.
///   * readers (`status`, dashboard): clone names + Arcs under the registry
///     guard, drop it, then take each host lock one at a time.
///   * `watch_for_silence`: same -- one host at a time, releasing between.
struct App {
    data_dir: PathBuf,
    /// Registry only. Per-host state lives behind its own lock so two hosts
    /// never wait on each other: everything the inner lock protects (high_seq,
    /// last_mac, segment, the append offset into that host's own files) is
    /// per-host, and two POSTs for the same host must serialise or they
    /// interleave bytes in events/{host}.ndjson.
    hosts: Mutex<HashMap<String, Arc<Mutex<Host>>>>,
    /// Host ids seen recently that are not enrolled. Every unknown id
    /// otherwise costs a filesystem miss, which turns the ingest port into
    /// disk load for anyone who can reach it and holds no credential.
    ///
    /// ponytail: TTL rather than an explicit invalidation, because `enroll`
    /// runs in a different process and cannot poke this one. A host enrolled
    /// while the collector is running starts working within
    /// UNENROLLED_TTL_SECS; restart if that wait is unacceptable.
    unenrolled: Mutex<HashMap<String, std::time::Instant>>,
    /// Admission control. With N requests in flight the collector buffers N
    /// bodies of up to MAX_BODY_BYTES each; unbounded, that is an OOM, and a
    /// `panic = "abort"` build turns an OOM into a fleet-wide blackout.
    ingest_permits: Arc<tokio::sync::Semaphore>,
    /// Cross-host Merkle state. Its own lock, taken last and briefly.
    merkle: Mutex<MerkleIndex>,
    /// Whether to seal batches at all. A kill switch for a feature that writes
    /// on the ingest path; ingest keeps working with it off, just uncommitted.
    merkle_enabled: bool,
}

/// How long a "not enrolled" answer stays cached. One minute: long enough that
/// a spray of unknown ids costs one stat each rather than one per request,
/// short enough that a genuine enrollment is picked up without a restart.
const UNENROLLED_TTL_SECS: u64 = 60;

/// Bound on the negative cache. Reached only under a spray of distinct ids, so
/// the crude fix -- drop everything and start over -- is the right one: it is
/// O(1), it cannot grow without bound, and the cost of a cleared cache is one
/// extra stat per real host.
const UNENROLLED_MAX: usize = 4096;

impl App {
    /// Find or lazily load a host, returning its own lock.
    ///
    /// The registry guard is dropped before the enrollment is read from disk,
    /// so a slow or missing file never blocks another host's ingest. Two
    /// concurrent first-contacts for the same host can therefore both load it;
    /// the first to re-acquire wins and the loser drops its copy. Both read the
    /// same bytes, so that is harmless.
    async fn host_entry(&self, host: &str) -> Result<Arc<Mutex<Host>>, (StatusCode, String)> {
        if let Some(existing) = self.hosts.lock().await.get(host) {
            return Ok(Arc::clone(existing));
        }

        {
            let mut miss = self.unenrolled.lock().await;
            match miss.get(host) {
                Some(seen) if seen.elapsed().as_secs() < UNENROLLED_TTL_SECS => {
                    return Err((StatusCode::FORBIDDEN, "host is not enrolled".to_string()));
                }
                Some(_) => {
                    miss.remove(host);
                }
                None => {}
            }
        }

        let Some(enrollment) = load_enrollment(&self.data_dir, host) else {
            eprintln!("WARNING: rejected batch from unenrolled host {:?}", host);
            let mut miss = self.unenrolled.lock().await;
            if miss.len() >= UNENROLLED_MAX {
                miss.clear();
            }
            miss.insert(host.to_string(), std::time::Instant::now());
            return Err((StatusCode::FORBIDDEN, "host is not enrolled".to_string()));
        };
        let Ok(k0) = parse_key(&enrollment.k0) else {
            eprintln!("CRITICAL: enrollment for {} has an unusable K0", host);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "enrollment is corrupt".to_string(),
            ));
        };
        let state = load_state(&self.data_dir, host);
        let loaded = Arc::new(Mutex::new(Host {
            enrollment,
            keys: HostKeys::new(k0),
            state,
        }));

        let mut reg = self.hosts.lock().await;
        Ok(Arc::clone(
            reg.entry(host.to_string()).or_insert(loaded),
        ))
    }

    fn new(data_dir: PathBuf, max_concurrent_ingest: usize) -> Self {
        App::with_merkle(data_dir, max_concurrent_ingest, true)
    }

    fn with_merkle(data_dir: PathBuf, max_concurrent_ingest: usize, merkle_enabled: bool) -> Self {
        let merkle = MerkleIndex::load(&data_dir);
        App {
            data_dir,
            hosts: Mutex::new(HashMap::new()),
            unenrolled: Mutex::new(HashMap::new()),
            ingest_permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_ingest)),
            merkle: Mutex::new(merkle),
            merkle_enabled,
        }
    }

    /// Every host and its lock, as a snapshot. The registry guard is released
    /// before the caller touches any of them.
    async fn host_snapshot(&self) -> Vec<(String, Arc<Mutex<Host>>)> {
        self.hosts
            .lock()
            .await
            .iter()
            .map(|(name, h)| (name.clone(), Arc::clone(h)))
            .collect()
    }
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

fn hex_string(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn batches_path(dir: &Path, host: &str) -> PathBuf {
    dir.join("batches").join(format!("{}.ndjson", host))
}

/// Global, not per host: level 2 is fleet-wide.
fn roots_path(dir: &Path) -> PathBuf {
    dir.join("roots.ndjson")
}

/// 64 hex characters back to 32 bytes, None for anything else. The collector
/// has no hex dependency of its own and does not need one for eight lines.
fn unhex(h: &str) -> Option<[u8; 32]> {
    if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
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

/// Push one line into the batch, and its leaf, together.
///
/// The single most breakable invariant in the Merkle layer is that
/// `pending_leaves[i]` is the leaf of the i-th line appended to the events
/// file. Every commit goes through this one function so a line type cannot be
/// added to one and forgotten in the other.
fn commit_line(out: &mut String, leaves: &mut Vec<[u8; 32]>, json: &str, leaf: [u8; 32]) {
    out.push_str(json);
    out.push('\n');
    leaves.push(leaf);
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

    // Load on first contact. An unenrolled host is refused: without K0 there is
    // nothing to verify against, and storing unverifiable records under a name
    // an attacker chose would be worse than refusing them.
    //
    // The registry lock is taken and released inside here; from this point on
    // the only lock held is this one host's, so every other host ingests in
    // parallel with this request.
    let host_entry = match app.host_entry(&host).await {
        Ok(h) => h,
        Err((code, err)) => return (code, Json(json!({"acked_seq": 0, "error": err}))),
    };
    let mut guard = host_entry.lock().await;
    // One deref_mut, then field-split. Lets `&state` and `&mut keys` be taken
    // at once in the loop below, which a bare guard would not allow.
    let entry = &mut *guard;

    let now: DateTime<Utc> = Utc::now();
    let mut out = String::with_capacity(body.len() + 256);
    let mut first_error: Option<String> = None;
    // Leaf per committed line, in append order. Empty means nothing was
    // stored, which means nothing is sealed -- an idempotent replay writes no
    // batch line at all.
    let mut pending_leaves: Vec<[u8; 32]> = Vec::new();
    let mut seq_lo = 0u64;
    let mut seq_hi = 0u64;

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
                let leaf = merkle::marker_leaf(s.as_bytes());
                commit_line(&mut out, &mut pending_leaves, &s, leaf);
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
                let leaf = merkle::marker_leaf(s.as_bytes());
                commit_line(&mut out, &mut pending_leaves, &s, leaf);
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
            // The record leaf commits to sealed_payload || raw(hash) -- the
            // agent's bytes only -- so a third party holding just the record can
            // recompute it. A record whose hash is not 32 raw bytes cannot have
            // verified; it is committed over its stored line instead, which at
            // least pins the evidence.
            let leaf = merkle::record_leaf(&rec).unwrap_or_else(|| merkle::marker_leaf(s.as_bytes()));
            if seq_lo == 0 {
                seq_lo = rec.seq;
            }
            seq_hi = rec.seq;
            commit_line(&mut out, &mut pending_leaves, &s, leaf);
        }

        entry.state.high_seq = rec.seq;
        entry.state.high_epoch = entry.state.high_epoch.max(rec.epoch);
        entry.state.last_mac = rec.hash.clone();
        entry.state.total_records += 1;
    }

    if !out.is_empty() {
        let path = events_path(&app.data_dir, &host);
        let bytes = std::mem::take(&mut out);

        // sync_all() is a blocking syscall. Run inline, it parks a tokio worker
        // thread in fsync, and under a fleet's worth of concurrent agents the
        // runtime stops making progress on anything else -- including
        // /healthz, which makes a busy collector look dead to whatever is
        // watching it. The blocking pool exists for exactly this.
        //
        // This host's guard IS held across the await, deliberately: two POSTs
        // for one host must not interleave their bytes. Other hosts are
        // unaffected, which is the whole point of the per-host lock.
        // Returns the byte range this append occupies. byte_start is read
        // from the open file under this host's lock, so two writers to one
        // host cannot both claim the same offset.
        let append = tokio::task::spawn_blocking(move || -> std::io::Result<(u64, u64)> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            let byte_start = f.metadata()?.len();
            f.write_all(bytes.as_bytes())?;
            f.sync_all()?;
            Ok((byte_start, byte_start.saturating_add(bytes.len() as u64)))
        })
        .await;

        // A JoinError means the blocking task panicked or was cancelled. Treat
        // it exactly like a write failure: nothing is known to be on disk, so
        // nothing may be acked. Never unwrap the join (PANIC POLICY).
        let (failure, range) = match append {
            Ok(Ok(range)) => (None, Some(range)),
            Ok(Err(e)) => (Some(e.to_string()), None),
            Err(join) => (Some(format!("append task did not complete: {}", join)), None),
        };

        if let Some(e) = failure {
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

        // Only now that the events bytes are durable is there anything to
        // commit to. Sealing before the append would commit to bytes that may
        // never exist.
        //
        // If this batch write fails, state rolls back to pre_batch and nothing
        // is acked -- even though the events bytes ARE on disk. That is
        // deliberate, and it is not a leak: the agent retries, the retried
        // records get appended a second time, and the second attempt commits
        // those bytes. The orphaned first copy is uncommitted bytes that no
        // batch line names, which is harmless precisely because batches commit
        // to byte ranges rather than to sequence numbers. Do not "fix" this
        // into acking a batch whose commitment was never written.
        // Both emptiness checks are redundant with `if !out.is_empty()` above,
        // since commit_line pushes a line and its leaf together and nothing
        // else writes to `out`. Kept as belt and braces on the invariant that
        // matters most here: never seal a batch that commits to no bytes.
        if app.merkle_enabled && !pending_leaves.is_empty() {
            let Some((byte_start, byte_end)) = range else {
                eprintln!("CRITICAL: events for {} were appended without a byte range", host);
                let acked = pre_batch.high_seq;
                entry.state = pre_batch;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"acked_seq": acked, "error": "storage write failed"})),
                );
            };

            let batch_id = entry.state.batches;
            let prev_chainhash = if entry.state.last_chainhash.is_empty() {
                GENESIS_MAC.to_string()
            } else {
                entry.state.last_chainhash.clone()
            };
            // One SHA-256 per record plus n-1 for the tree: microseconds for a
            // 500-record batch, against two fsyncs in the same section.
            let chainhash = merkle::root(&pending_leaves);
            let chainhash_hex = hex_string(&chainhash);

            let line = BatchLine {
                v: 1,
                batch_id,
                host: host.clone(),
                sealed_at: now.to_rfc3339(),
                chainhash: chainhash_hex.clone(),
                prev_chainhash,
                count: pending_leaves.len().min(u32::MAX as usize) as u32,
                seq_lo,
                seq_hi,
                segment: entry.state.segment,
                byte_start,
                byte_end,
                leaves: pending_leaves.iter().map(hex_string).collect(),
            };

            let Ok(mut encoded) = serde_json::to_string(&line) else {
                eprintln!("CRITICAL: could not serialize batch {} for {}", batch_id, host);
                let acked = pre_batch.high_seq;
                entry.state = pre_batch;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"acked_seq": acked, "error": "batch commit failed"})),
                );
            };
            encoded.push('\n');

            let bpath = batches_path(&app.data_dir, &host);
            let written = tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
                if let Some(parent) = bpath.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&bpath)?;
                let line_offset = f.metadata()?.len();
                f.write_all(encoded.as_bytes())?;
                f.sync_all()?;
                Ok(line_offset)
            })
            .await;

            let line_offset = match written {
                Ok(Ok(offset)) => offset,
                Ok(Err(e)) => {
                    eprintln!("CRITICAL: could not commit batch {} for {}: {}", batch_id, host, e);
                    let acked = pre_batch.high_seq;
                    entry.state = pre_batch;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"acked_seq": acked, "error": "batch commit failed"})),
                    );
                }
                Err(join) => {
                    eprintln!("CRITICAL: batch commit task for {} did not complete: {}", host, join);
                    let acked = pre_batch.high_seq;
                    entry.state = pre_batch;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"acked_seq": acked, "error": "batch commit failed"})),
                    );
                }
            };

            entry.state.batches = batch_id.saturating_add(1);
            entry.state.last_chainhash = chainhash_hex;
            entry.state.last_committed_seq = seq_hi.max(entry.state.last_committed_seq);

            // Still under this host's lock, take the index lock -- host then
            // merkle, never the reverse -- and release it immediately. Pure
            // in-memory work only.
            let mut index = app.merkle.lock().await;
            index
                .batches
                .entry(host.clone())
                .or_default()
                .push(BatchIndexEntry {
                    batch_id,
                    seq_lo,
                    seq_hi,
                    segment: line.segment,
                    byte_start,
                    byte_end,
                    count: line.count,
                    sealed_at: line.sealed_at,
                    line_offset,
                });
            // Queued for the next fleet-wide root. The chainhash is cached
            // here so the sealer never needs this host's lock or its files.
            index.pending.push(PendingBatch {
                host: host.clone(),
                batch_id,
                chainhash,
            });
            drop(index);
        }
    }

    entry.state.last_seen = Some(now.to_rfc3339());
    if entry.state.silent {
        eprintln!("host {} is reporting again", host);
        entry.state.silent = false;
    }

    let acked = entry.state.high_seq;
    let state_copy = entry.state.clone();
    drop(guard);

    // Off the runtime threads for the same reason as the append: write_atomic
    // ends in its own sync_all().
    let dir = app.data_dir.clone();
    let host_for_save = host.clone();
    let _ = tokio::task::spawn_blocking(move || {
        save_state(&dir, &host_for_save, &state_copy);
    })
    .await;

    match first_error {
        Some(err) => (
            StatusCode::CONFLICT,
            Json(json!({"acked_seq": acked, "error": err})),
        ),
        None => (StatusCode::OK, Json(json!({"acked_seq": acked}))),
    }
}

async fn status(State(app): State<Arc<App>>) -> impl IntoResponse {
    // Registry guard released before any host lock is taken (see LOCK ORDER).
    // ponytail: a host mid-fsync makes this wait on that one host, not on the
    // fleet. Give HostState an atomic snapshot if that ever shows up in a
    // latency graph.
    let mut summary = Vec::new();
    for (name, entry) in app.host_snapshot().await {
        let h = entry.lock().await;
        summary.push(json!({
            "host": name,
            "high_seq": h.state.high_seq,
            "epoch": h.state.high_epoch,
            "records": h.state.total_records,
            "breaks": h.state.breaks,
            "segment": h.state.segment,
            "last_seen": h.state.last_seen,
            "silent": h.state.silent,
        }));
    }
    Json(json!({"hosts": summary}))
}

async fn health() -> &'static str {
    "ok\n"
}

/// Admission control for the ingest route only.
///
/// Runs before the handler, and therefore before the body extractor buffers up
/// to MAX_BODY_BYTES into a String -- which is the whole point: the memory this
/// bounds is allocated by the extractor, so gating after it would bound
/// nothing.
///
/// Sheds with 503, never 409. The shipper advances its cursor past a 409 on the
/// grounds that the evidence is already off-box; returning one under load would
/// drop records on the floor for the one reason that has nothing to do with
/// tampering. A 503 leaves them in the WAL for the next poll.
async fn admit_ingest(
    State(app): State<Arc<App>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Ok(_permit) = Arc::clone(&app.ingest_permits).try_acquire_owned() else {
        eprintln!("WARNING: shedding an ingest batch: at capacity");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "5")],
            Json(json!({"acked_seq": 0, "error": "collector at capacity, retry"})),
        )
            .into_response();
    };
    next.run(req).await
}

/// The agent-facing socket. Built here rather than inline in `serve` so the
/// concurrency tests drive the same router the fleet does, admission control
/// included.
///
/// The semaphore layer wraps ONLY /v1/ingest. /healthz and /v1/status must keep
/// answering while ingest is saturated -- a collector that fails its own health
/// check under normal fleet load reads as dead and gets restarted, which is
/// strictly worse than being slow.
fn ingest_router(app: Arc<App>) -> Router {
    Router::new()
        .route(
            "/v1/ingest",
            post(ingest).layer(axum::middleware::from_fn_with_state(
                Arc::clone(&app),
                admit_ingest,
            )),
        )
        .route("/v1/status", get(status))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(app)
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

        // One host lock at a time, registry guard already released. Holding
        // the registry across the whole sweep would park every ingest on this
        // background task once a minute.
        for (name, entry) in app.host_snapshot().await {
            let mut h = entry.lock().await;
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
// The root sealer (server.md 2.7)
// ---------------------------------------------------------

/// How often the sealer wakes to check its triggers. Both triggers are
/// coarse -- an interval in minutes, a batch count in the hundreds -- so a
/// tick finer than this buys nothing but wakeups.
const ROOT_TICK_SECS: u64 = 10;

/// Seal every pending batch into one fleet-wide root, if either trigger is due.
///
/// Split out of the loop so tests can fire it directly instead of waiting on a
/// tick. Returns the root_id sealed, or None when there was nothing to do.
///
/// The lock discipline is the whole correctness argument, and it is short:
/// this function takes the INDEX lock and no other, ever. It never takes a
/// host lock, which is what keeps it off the ingest path and the lock graph
/// acyclic (see LOCK ORDER). Both critical sections are pure in-memory work;
/// the hashing and the fsync happen with nothing held.
async fn seal_once(app: &Arc<App>, interval_secs: u64, max_batches: usize) -> Option<u64> {
    let (snapshot, root_id, prev_root) = {
        let index = app.merkle.lock().await;
        // A quiet fleet seals nothing. Empty roots would cost one blockchain
        // transaction each to commit to no records at all.
        if index.pending.is_empty() {
            return None;
        }
        let due = index.pending.len() >= max_batches
            || index.last_seal.elapsed().as_secs() >= interval_secs;
        if !due {
            return None;
        }
        (
            index.pending.clone(),
            index.next_root_id,
            index.last_root.clone(),
        )
    };

    // No lock held from here to the append. Ingest keeps running, and anything
    // it seals meanwhile lands after this snapshot in `pending` and rolls into
    // the next root.
    let sealed_count = snapshot.len();
    let mut sorted = snapshot;
    sorted.sort_by(|a, b| a.host.cmp(&b.host).then(a.batch_id.cmp(&b.batch_id)));

    // Hosts ascending, batches ascending within a host. This order IS the
    // format: a verifier that sorts differently computes a different root and
    // every proof issued against it fails.
    let leaves: Vec<[u8; 32]> = sorted
        .iter()
        .map(|p| merkle::batch_leaf(&p.host, p.batch_id, &p.chainhash))
        .collect();
    let root = merkle::root(&leaves);

    let mut covers: Vec<RootCover> = Vec::new();
    for p in &sorted {
        match covers.last_mut() {
            Some(c) if c.host == p.host => {
                c.batch_hi = p.batch_id;
                c.chainhashes.push(hex_string(&p.chainhash));
            }
            _ => covers.push(RootCover {
                host: p.host.clone(),
                batch_lo: p.batch_id,
                batch_hi: p.batch_id,
                chainhashes: vec![hex_string(&p.chainhash)],
            }),
        }
    }

    let line = RootLine {
        v: 1,
        root_id,
        sealed_at: Utc::now().to_rfc3339(),
        root: hex_string(&root),
        prev_root,
        leaf_count: leaves.len() as u64,
        covers,
    };
    let Ok(mut encoded) = serde_json::to_string(&line) else {
        eprintln!("CRITICAL: could not serialize root {}", root_id);
        return None;
    };
    encoded.push('\n');

    let path = roots_path(&app.data_dir);
    let written = tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let line_offset = f.metadata()?.len();
        f.write_all(encoded.as_bytes())?;
        f.sync_all()?;
        Ok(line_offset)
    })
    .await;

    let line_offset = match written {
        Ok(Ok(offset)) => offset,
        // Nothing was written, so `pending` is deliberately left alone: the
        // same batches roll into the next attempt under the same root_id. A
        // root that was never appended simply never existed, which is what
        // makes retrying it safe rather than a double-commitment.
        Ok(Err(e)) => {
            eprintln!("CRITICAL: could not seal root {}: {}", root_id, e);
            return None;
        }
        Err(join) => {
            eprintln!("CRITICAL: root seal task for {} did not complete: {}", root_id, join);
            return None;
        }
    };

    let mut index = app.merkle.lock().await;
    // Exactly the prefix that was snapshotted. Anything ingest appended while
    // the lock was released sits after it and is untouched, so no batch is
    // dropped and none lands in two roots.
    let take = sealed_count.min(index.pending.len());
    index.pending.drain(..take);
    let still_pending = index.pending.len();
    index.next_root_id = root_id.saturating_add(1);
    index.last_root = line.root.clone();
    index.last_seal = std::time::Instant::now();
    index.roots.push(RootIndexEntry {
        root_id,
        sealed_at: line.sealed_at,
        root: line.root,
        line_offset,
        covers: line
            .covers
            .into_iter()
            .map(|c| (c.host, c.batch_lo, c.batch_hi))
            .collect(),
    });
    drop(index);

    eprintln!(
        "sealed root {} over {} batch(es); {} queued since",
        root_id, take, still_pending
    );
    Some(root_id)
}

/// Level 2: one periodic, fleet-wide root over every batch sealed since the
/// last one. Runs alongside `watch_for_silence` and, like it, holds no lock
/// across any I/O.
async fn seal_roots(app: Arc<App>, interval_secs: u64, max_batches: usize) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(ROOT_TICK_SECS));
    loop {
        tick.tick().await;
        seal_once(&app, interval_secs, max_batches).await;
    }
}

// ---------------------------------------------------------
// merkle-audit (server.md 2.9, step 6)
// ---------------------------------------------------------
//
// Everything below re-derives commitments from stored bytes and nothing else.
// No K0, no network, no in-memory index: an auditor who is handed a copy of the
// data directory can run this and get the same answer the collector would.

/// The leaf of one stored line, recomputed exactly as ingest computed it.
///
/// A record line commits to the agent's bytes only -- `sealed_payload ||
/// raw(hash)` -- so a third party holding just the record can rebuild it. Every
/// other line, including a record whose hash is not 32 raw bytes, commits to
/// the exact bytes the collector wrote. Ingest makes the same choice in the
/// same order; if these two ever disagree, every proof for the batch is wrong,
/// which is what the acceptance tests pin.
pub(crate) fn leaf_for_line(line: &str) -> [u8; 32] {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("record").cloned())
        .and_then(|r| serde_json::from_value::<AgentLog>(r).ok())
        .and_then(|rec| merkle::record_leaf(&rec))
        .unwrap_or_else(|| merkle::marker_leaf(line.as_bytes()))
}

/// A batch's leaves, recomputed from the events bytes the batch names.
///
/// None when the range no longer reads at all -- which is itself a finding, and
/// the caller reports it rather than treating it as an empty batch.
pub(crate) fn batch_leaves_from_events(events: &[u8], b: &BatchLine) -> Option<Vec<[u8; 32]>> {
    let slice = events.get(b.byte_start as usize..b.byte_end as usize)?;
    let text = std::str::from_utf8(slice).ok()?;
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(leaf_for_line)
            .collect(),
    )
}

/// Level-2 leaves of a root, in the canonical order the root line already
/// stores them in. None if any chainhash is not 64 hex characters.
fn level2_leaves(covers: &[RootCover]) -> Option<Vec<[u8; 32]>> {
    let mut leaves = Vec::new();
    for c in covers {
        for (i, h) in c.chainhashes.iter().enumerate() {
            let chainhash = unhex(h)?;
            leaves.push(merkle::batch_leaf(
                &c.host,
                c.batch_lo.saturating_add(i as u64),
                &chainhash,
            ));
        }
    }
    Some(leaves)
}

#[derive(Default)]
pub(crate) struct AuditReport {
    /// (host, batches, committed lines).
    rows: Vec<(String, u64, u64)>,
    roots: u64,
    /// One line per finding, in the order they were found. Empty means intact.
    pub(crate) divergences: Vec<String>,
}

/// Recompute every commitment under `dir`; report what no longer matches.
///
/// Roots are always audited even when `only_host` is given: a root is
/// fleet-wide and recomputes from the chainhashes in its own line, so checking
/// it needs no host's files. Only the cross-check of those chainhashes against
/// the batch files is limited to the hosts that were audited.
pub(crate) fn audit(dir: &Path, only_host: Option<&str>) -> AuditReport {
    let mut report = AuditReport::default();
    let mut sealed: HashMap<(String, u64), String> = HashMap::new();

    let hosts: Vec<String> = match only_host {
        Some(h) => vec![h.to_string()],
        None => {
            let mut found: Vec<String> = std::fs::read_dir(dir.join("batches"))
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .strip_suffix(".ndjson")
                        .map(str::to_string)
                })
                .collect();
            found.sort();
            found
        }
    };

    for host in &hosts {
        let events = std::fs::read(events_path(dir, host)).unwrap_or_default();
        let raw = std::fs::read_to_string(batches_path(dir, host)).unwrap_or_default();

        let mut batches: Vec<BatchLine> = Vec::new();
        for (i, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<BatchLine>(line) {
                Ok(b) => batches.push(b),
                Err(e) => report.divergences.push(format!(
                    "{}: batch line {} does not parse: {}",
                    host,
                    i + 1,
                    e
                )),
            }
        }

        let mut prev = GENESIS_MAC.to_string();
        let mut lines = 0u64;
        for (i, b) in batches.iter().enumerate() {
            let at = format!("{} batch {}", host, b.batch_id);
            if b.batch_id != i as u64 {
                report.divergences.push(format!(
                    "{}: batch ids are not dense; expected {} at this position. A batch line \
                     was deleted, reordered, or inserted.",
                    at, i
                ));
            }
            if b.host != *host {
                report.divergences.push(format!(
                    "{}: batch line claims host {:?}, but it is stored under {:?}",
                    at, b.host, host
                ));
            }
            if b.prev_chainhash != prev {
                report.divergences.push(format!(
                    "{}: prev_chainhash {} does not match the previous batch's chainhash {}. \
                     The batch chain was cut.",
                    at, b.prev_chainhash, prev
                ));
            }
            prev = b.chainhash.clone();
            sealed.insert((host.clone(), b.batch_id), b.chainhash.clone());

            let Some(leaves) = batch_leaves_from_events(&events, b) else {
                report.divergences.push(format!(
                    "{}: the committed byte range {}..{} no longer reads from the events file. \
                     Lines were removed or the file was truncated.",
                    at, b.byte_start, b.byte_end
                ));
                continue;
            };
            lines = lines.saturating_add(leaves.len() as u64);

            if leaves.len() != b.count as usize {
                report.divergences.push(format!(
                    "{}: the committed byte range now holds {} line(s), but the batch commits \
                     to {}",
                    at,
                    leaves.len(),
                    b.count
                ));
            }
            if leaves.len() != b.leaves.len() {
                report.divergences.push(format!(
                    "{}: {} recomputed leaf/leaves against {} stored",
                    at,
                    leaves.len(),
                    b.leaves.len()
                ));
            }
            for (j, l) in leaves.iter().enumerate() {
                let recomputed = hex_string(l);
                match b.leaves.get(j) {
                    Some(stored) if *stored == recomputed => {}
                    Some(stored) => report.divergences.push(format!(
                        "{}: leaf {} recomputes to {} but the commitment says {}. Those bytes \
                         were altered after they were sealed.",
                        at, j, recomputed, stored
                    )),
                    None => report.divergences.push(format!(
                        "{}: leaf {} has no stored counterpart",
                        at, j
                    )),
                }
            }

            let recomputed = hex_string(&merkle::root(&leaves));
            if recomputed != b.chainhash {
                report.divergences.push(format!(
                    "{}: chainhash recomputes to {} but the batch line says {}",
                    at, recomputed, b.chainhash
                ));
            }
        }

        report
            .rows
            .push((host.clone(), batches.len() as u64, lines));
    }

    // Roots. Each one recomputes from the chainhashes it carries, so this half
    // stands on its own even if no host's files are present at all.
    let raw = std::fs::read_to_string(roots_path(dir)).unwrap_or_default();
    let mut prev_root = GENESIS_MAC.to_string();
    let mut expected_id = 0u64;
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let r: RootLine = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                report
                    .divergences
                    .push(format!("root line {} does not parse: {}", i + 1, e));
                continue;
            }
        };
        report.roots = report.roots.saturating_add(1);
        let at = format!("root {}", r.root_id);

        if r.root_id != expected_id {
            report.divergences.push(format!(
                "{}: root ids are not dense; expected {} at this position. A root line was \
                 deleted, and every batch it covered now has no covering root.",
                at, expected_id
            ));
        }
        expected_id = r.root_id.saturating_add(1);

        if r.prev_root != prev_root {
            report.divergences.push(format!(
                "{}: prev_root {} does not match the previous root {}. The root chain was cut.",
                at, r.prev_root, prev_root
            ));
        }
        prev_root = r.root.clone();

        // The canonical order is part of the format: hosts ascending, batches
        // ascending within a host. A root written in any other order is one no
        // independent verifier can reproduce.
        if r.covers.windows(2).any(|w| match w {
            [a, b] => a.host >= b.host,
            _ => false,
        }) {
            report.divergences.push(format!(
                "{}: covers is not sorted by host ascending, so the level-2 leaf order cannot \
                 be reproduced by a verifier",
                at
            ));
        }
        let mut counted = 0u64;
        for c in &r.covers {
            let span = c.batch_hi.saturating_sub(c.batch_lo).saturating_add(1);
            if c.chainhashes.len() as u64 != span {
                report.divergences.push(format!(
                    "{}: {} covers batches {}..={} ({}) but carries {} chainhash(es)",
                    at,
                    c.host,
                    c.batch_lo,
                    c.batch_hi,
                    span,
                    c.chainhashes.len()
                ));
            }
            counted = counted.saturating_add(c.chainhashes.len() as u64);
            for (j, h) in c.chainhashes.iter().enumerate() {
                let batch_id = c.batch_lo.saturating_add(j as u64);
                if let Some(stored) = sealed.get(&(c.host.clone(), batch_id)) {
                    if stored != h {
                        report.divergences.push(format!(
                            "{}: covers {} batch {} with chainhash {}, but that batch line says \
                             {}",
                            at, c.host, batch_id, h, stored
                        ));
                    }
                }
            }
        }
        if counted != r.leaf_count {
            report.divergences.push(format!(
                "{}: leaf_count says {} but covers holds {}",
                at, r.leaf_count, counted
            ));
        }

        let Some(leaves) = level2_leaves(&r.covers) else {
            report.divergences.push(format!(
                "{}: a chainhash in covers is not 64 hex characters, so the root cannot be \
                 recomputed",
                at
            ));
            continue;
        };
        let recomputed = hex_string(&merkle::root(&leaves));
        if recomputed != r.root {
            report.divergences.push(format!(
                "{}: recomputes to {} but the root line says {}",
                at, recomputed, r.root
            ));
        }
    }

    report
}

fn cmd_merkle_audit(dir: &Path, host: Option<&str>) -> Result<(), anyhow::Error> {
    if let Some(h) = host {
        if !valid_host_id(h) {
            anyhow::bail!("host id may only contain letters, digits, '-', '.', '_'");
        }
    }
    let report = audit(dir, host);

    for finding in &report.divergences {
        println!("{}", finding);
    }
    if !report.divergences.is_empty() {
        println!();
    }

    println!("{:<24} {:>8} {:>10}", "HOST", "BATCHES", "LINES");
    let mut batches = 0u64;
    let mut lines = 0u64;
    for (h, b, l) in &report.rows {
        println!("{:<24} {:>8} {:>10}", h, b, l);
        batches = batches.saturating_add(*b);
        lines = lines.saturating_add(*l);
    }

    println!();
    println!("hosts         {}", report.rows.len());
    println!("batches       {}", batches);
    println!("lines         {}", lines);
    println!("roots         {}", report.roots);
    println!("divergences   {}", report.divergences.len());
    if report.divergences.is_empty() {
        println!("RESULT        intact");
    } else {
        println!("RESULT        TAMPERED. The store no longer matches its own commitments.");
    }
    println!();
    println!("This checks the collector against ITS OWN commitments, with no K0 and no chain.");
    println!("It does not prove the records are authentic (that is the HMAC under K0), and it");
    println!("cannot see a record that was dropped before it was ever batched.");
    Ok(())
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

        Command::MerkleAudit { host } => cmd_merkle_audit(&cli.data_dir, host.as_deref()),

        Command::Serve {
            listen,
            silence_secs,
            max_concurrent_ingest,
            merkle,
            root_interval_secs,
            root_max_batches,
            dashboard_listen,
        } => {
            std::fs::create_dir_all(cli.data_dir.join("hosts"))?;
            std::fs::create_dir_all(cli.data_dir.join("events"))?;

            // A zero here would wedge ingest permanently, so it is floored.
            let permits = max_concurrent_ingest.max(1);
            let app = Arc::new(App::with_merkle(cli.data_dir.clone(), permits, merkle));
            let (indexed, rooted, pending) = {
                let index = app.merkle.lock().await;
                (
                    index.batches.values().map(Vec::len).sum::<usize>(),
                    index.roots.len(),
                    index.pending.len(),
                )
            };

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
                        Arc::new(Mutex::new(Host {
                            enrollment,
                            keys: HostKeys::new(k0),
                            state,
                        })),
                    );
                }
            }

            let enrolled = app.hosts.lock().await.len();

            tokio::spawn(watch_for_silence(Arc::clone(&app), silence_secs));

            // A zero here would seal a root per tick over a single batch, which
            // is one blockchain transaction per ten seconds.
            if merkle {
                tokio::spawn(seal_roots(
                    Arc::clone(&app),
                    root_interval_secs,
                    root_max_batches.max(1),
                ));
            }

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

            let router = ingest_router(Arc::clone(&app));

            let listener = tokio::net::TcpListener::bind(&listen).await?;
            eprintln!(
                "edr-collector listening on {} | {} host(s) enrolled | data {:?} | \
                 {} concurrent ingest | merkle {} ({} batches, {} roots, {} pending)",
                listen,
                enrolled,
                cli.data_dir,
                permits,
                if merkle { "on" } else { "off" },
                indexed,
                rooted,
                pending
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

// ---------------------------------------------------------
// Concurrency tests (server.md 2.11.6)
// ---------------------------------------------------------
//
// The design target is hundreds of hosts each POSTing up to 500 records every
// few seconds. What these pin down is that different hosts never wait on each
// other, that the same host always does, and that an overloaded collector sheds
// with a status the shipper treats as retryable.
//
// Every test runs under a wall-clock timeout. A lock inversion should fail CI
// in seconds rather than hang it until the job is killed.
#[cfg(test)]
pub(crate) mod concurrency_tests {
    use super::*;
    use edr_record::record_mac;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::ServiceExt;

    const DEADLOCK_GUARD: std::time::Duration = std::time::Duration::from_secs(60);

    /// A data dir that removes itself. No tempfile dependency for four lines.
    pub(crate) struct TempDir(pub(crate) PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn temp_dir() -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "edr-collector-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(dir.join("hosts"));
        let _ = std::fs::create_dir_all(dir.join("events"));
        TempDir(dir)
    }

    pub(crate) fn enroll_for_test(dir: &Path, host: &str, k0: &[u8; 32]) {
        let enrollment = Enrollment {
            k0: hex_of(k0),
            build_id: None,
            enrolled_at: Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string(&enrollment).expect("enrollment serialises");
        write_atomic(&enroll_path(dir, host), &json).expect("enrollment written");
    }

    pub(crate) fn hex_of(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub(crate) fn seal_one(k0: &[u8; 32], seq: u64, prev: &str) -> AgentLog {
        let mut log = AgentLog {
            seq,
            epoch: 0,
            timestamp: "2026-08-27T10:00:00+00:00".to_string(),
            severity: "INFO".to_string(),
            event_type: "PROCESS_EXEC".to_string(),
            process_name: "bash".to_string(),
            prev_hash: prev.to_string(),
            ..Default::default()
        };
        log.hash = record_mac(k0, &log);
        log
    }

    /// `count` sealed records starting at `from_seq`, plus the hash the next
    /// batch must chain from.
    pub(crate) fn batch(k0: &[u8; 32], from_seq: u64, count: u64, prev: &str) -> (String, String) {
        let mut body = String::new();
        let mut prev = prev.to_string();
        for seq in from_seq..from_seq + count {
            let rec = seal_one(k0, seq, &prev);
            prev = rec.hash.clone();
            body.push_str(&serde_json::to_string(&rec).expect("record serialises"));
            body.push('\n');
        }
        (body, prev)
    }

    pub(crate) fn headers_for(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("X-EDR-Host", host.parse().expect("host is a valid header"));
        h
    }

    pub(crate) async fn post_batch(app: &Arc<App>, host: &str, body: String) -> StatusCode {
        ingest(State(Arc::clone(app)), headers_for(host), body)
            .await
            .into_response()
            .status()
    }

    /// Every line of a host's store, parsed. Catches interleaved or partial
    /// writes: a torn line does not parse.
    pub(crate) fn stored_lines(dir: &Path, host: &str) -> Vec<serde_json::Value> {
        let raw = std::fs::read_to_string(events_path(dir, host)).unwrap_or_default();
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .unwrap_or_else(|e| panic!("torn or interleaved line {:?}: {}", l, e))
            })
            .collect()
    }

    /// 50 hosts ingesting at once, 10 sequential batches each.
    ///
    /// Different hosts share nothing, so every batch must commit cleanly. If
    /// the registry lock were still held across the append this would pass but
    /// take 500 fsyncs of wall clock; what it actually proves is that no host's
    /// bytes land in another host's file and no line is torn.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fifty_hosts_ingest_in_parallel() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 64));

        const HOSTS: u64 = 50;
        const BATCHES: u64 = 10;
        const PER_BATCH: u64 = 20;

        let mut keys = Vec::new();
        for i in 0..HOSTS {
            let host = format!("host-{:02}", i);
            let mut k0 = [0u8; 32];
            k0[0] = i as u8;
            k0[1] = 7;
            enroll_for_test(&dir.0, &host, &k0);
            keys.push((host, k0));
        }

        let run = async {
            let mut tasks = Vec::new();
            for (host, k0) in keys.clone() {
                let app = Arc::clone(&app);
                tasks.push(tokio::spawn(async move {
                    // Sequential within a host: seq must not skip, or the
                    // collector correctly reports a gap.
                    let mut prev = GENESIS_MAC.to_string();
                    for b in 0..BATCHES {
                        let (body, next) = batch(&k0, b * PER_BATCH + 1, PER_BATCH, &prev);
                        prev = next;
                        let code = post_batch(&app, &host, body).await;
                        assert_eq!(code, StatusCode::OK, "host {} batch {}", host, b);
                    }
                }));
            }
            for t in tasks {
                t.await.expect("ingest task did not panic");
            }
        };
        tokio::time::timeout(DEADLOCK_GUARD, run)
            .await
            .expect("deadlock guard: parallel ingest did not finish");

        for (host, _) in &keys {
            let lines = stored_lines(&dir.0, host);
            assert_eq!(
                lines.len() as u64,
                BATCHES * PER_BATCH,
                "host {} stored the wrong number of lines",
                host
            );
            for (i, line) in lines.iter().enumerate() {
                let rec = line.get("record").expect("a stored record, not a marker");
                assert_eq!(
                    rec.get("seq").and_then(|v| v.as_u64()),
                    Some(i as u64 + 1),
                    "host {} line {} is out of order",
                    host,
                    i
                );
                assert_eq!(
                    line.get("verified").and_then(|v| v.as_bool()),
                    Some(true),
                    "host {} line {} did not verify",
                    host,
                    i
                );
            }
        }
    }

    /// Eight identical batches for one host, at once.
    ///
    /// Exactly one may be stored; the other seven must fall through the
    /// `seq <= high_seq` replay check and store nothing. This is what a shipper
    /// retrying after a client-side timeout actually does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_host_identical_batches_store_once() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 64));
        let k0 = [9u8; 32];
        enroll_for_test(&dir.0, "dup", &k0);

        let (body, _) = batch(&k0, 1, 25, GENESIS_MAC);

        let run = async {
            let mut tasks = Vec::new();
            for _ in 0..8 {
                let app = Arc::clone(&app);
                let body = body.clone();
                tasks.push(tokio::spawn(
                    async move { post_batch(&app, "dup", body).await },
                ));
            }
            for t in tasks {
                let code = t.await.expect("ingest task did not panic");
                assert_eq!(code, StatusCode::OK, "a replay must not be an error");
            }
        };
        tokio::time::timeout(DEADLOCK_GUARD, run)
            .await
            .expect("deadlock guard: same-host replay did not finish");

        let lines = stored_lines(&dir.0, "dup");
        assert_eq!(lines.len(), 25, "a replayed batch was stored more than once");
    }

    /// Eight *different* batches for one host, at once.
    ///
    /// They arrive in an arbitrary order, so most will not chain -- that is
    /// detection working, and the collector stores the record anyway with a
    /// CHAIN_BREAK marker in front of it. What must hold regardless is that the
    /// file is never corrupt: every line parses, so no two writers interleaved
    /// their bytes, and no batch was torn in half.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_host_concurrent_writers_never_interleave() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 64));
        let k0 = [11u8; 32];
        enroll_for_test(&dir.0, "racy", &k0);

        let run = async {
            let mut tasks = Vec::new();
            for b in 0..8u64 {
                let app = Arc::clone(&app);
                let (body, _) = batch(&k0, b * 30 + 1, 30, GENESIS_MAC);
                tasks.push(tokio::spawn(
                    async move { post_batch(&app, "racy", body).await },
                ));
            }
            for t in tasks {
                let code = t.await.expect("ingest task did not panic");
                assert!(
                    code == StatusCode::OK || code == StatusCode::CONFLICT,
                    "out-of-order batches are detection, not failure: got {}",
                    code
                );
            }
        };
        tokio::time::timeout(DEADLOCK_GUARD, run)
            .await
            .expect("deadlock guard: concurrent same-host writers did not finish");

        // The assertion that matters: stored_lines panics on any line that does
        // not parse, which is what a torn or interleaved write looks like.
        let lines = stored_lines(&dir.0, "racy");
        assert!(!lines.is_empty(), "nothing was stored at all");
        for line in &lines {
            assert!(
                line.get("record").is_some() || line.get("collector_event").is_some(),
                "a line is neither a record nor a marker: {}",
                line
            );
        }
    }

    /// Overload sheds with 503 and a Retry-After, never 409.
    ///
    /// 409 is the one wrong answer: the shipper advances its cursor past a 409
    /// on the grounds that the evidence is already off-box, so returning one
    /// here would drop records for a reason that has nothing to do with
    /// tampering. Deterministic -- every permit is held for the duration rather
    /// than raced for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overload_sheds_with_503_and_retries_succeed() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 2));
        let k0 = [13u8; 32];
        enroll_for_test(&dir.0, "busy", &k0);

        let (body, _) = batch(&k0, 1, 10, GENESIS_MAC);
        let request = |body: String| {
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/ingest")
                .header("X-EDR-Host", "busy")
                .body(axum::body::Body::from(body))
                .expect("request builds")
        };

        let held: Vec<_> = (0..2)
            .map(|_| {
                Arc::clone(&app.ingest_permits)
                    .try_acquire_owned()
                    .expect("permit is free")
            })
            .collect();

        let shed = ingest_router(Arc::clone(&app))
            .oneshot(request(body.clone()))
            .await
            .expect("router responds");
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            shed.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("5")),
            "a shed batch must tell the shipper when to come back"
        );

        // Liveness: /healthz must answer while ingest is saturated. A collector
        // that fails its own health check under load gets restarted, which is
        // worse than being slow.
        let health = ingest_router(Arc::clone(&app))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(
            health.status(),
            StatusCode::OK,
            "healthz stalled behind saturated ingest"
        );

        drop(held);

        // The retry of a shed batch commits, because nothing was acked.
        let retried = ingest_router(Arc::clone(&app))
            .oneshot(request(body))
            .await
            .expect("router responds");
        assert_eq!(retried.status(), StatusCode::OK);
        assert_eq!(stored_lines(&dir.0, "busy").len(), 10);
    }

    /// The refactor's whole point, pinned: a host parked mid-ingest must not
    /// stop another host from ingesting.
    ///
    /// Host A's lock is taken by the test and held, then a real `ingest` for A
    /// is spawned -- it parks on that lock with its handler half-executed,
    /// standing in for A sitting in fsync. Host B then posts and must finish.
    ///
    /// This is the test that fails if anyone reintroduces a fleet-wide lock on
    /// the ingest path, which is the specific hazard the Merkle index lock
    /// creates in the next step: A's parked handler would be holding it, and B
    /// would wait behind a host it shares nothing with. Verified to fail
    /// against exactly that mutation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_host_parked_mid_ingest_does_not_block_another() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 64));
        let k0 = [17u8; 32];
        enroll_for_test(&dir.0, "slow", &k0);
        enroll_for_test(&dir.0, "quick", &k0);

        // Take host "slow"'s lock and keep it, so its handler cannot proceed.
        let slow = app.host_entry("slow").await.expect("slow is enrolled");
        let held = slow.lock().await;

        let parked = {
            let app = Arc::clone(&app);
            let (body, _) = batch(&k0, 1, 10, GENESIS_MAC);
            tokio::spawn(async move { post_batch(&app, "slow", body).await })
        };
        // Let it get as far as it can, which is the host lock it cannot have.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!parked.is_finished(), "the parked ingest was supposed to block");

        let (body, _) = batch(&k0, 1, 10, GENESIS_MAC);
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            post_batch(&app, "quick", body),
        )
        .await
        .expect("host 'quick' waited on host 'slow' -- something fleet-wide is held across ingest");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(stored_lines(&dir.0, "quick").len(), 10);

        // Release, and the parked handler completes normally.
        drop(held);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), parked)
                .await
                .expect("parked ingest never resumed")
                .expect("parked ingest did not panic"),
            StatusCode::OK
        );
    }

    /// An unknown host id is refused from memory the second time, without
    /// touching the filesystem again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unenrolled_hosts_are_refused_from_the_negative_cache() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));

        for _ in 0..3 {
            assert_eq!(
                post_batch(&app, "never-enrolled", "\n".to_string()).await,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            app.unenrolled.lock().await.len(),
            1,
            "the miss should be cached once, not once per request"
        );

        // Enrolling clears the way once the entry ages out; until then the
        // cached refusal stands, which is the documented trade.
        assert!(app.hosts.lock().await.is_empty());
    }
}

// ---------------------------------------------------------
// Merkle batching tests (server.md 2.6)
// ---------------------------------------------------------
#[cfg(test)]
pub(crate) mod merkle_batch_tests {
    use super::concurrency_tests::*;
    use super::*;

    /// Every batch line a host has sealed.
    pub(crate) fn batch_lines(dir: &Path, host: &str) -> Vec<BatchLine> {
        let raw = std::fs::read_to_string(batches_path(dir, host)).unwrap_or_default();
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("batch line {:?}: {}", l, e)))
            .collect()
    }

    /// A batch commits to the bytes it actually wrote.
    ///
    /// This is the assertion the whole feature rests on: re-read the events
    /// file over the batch's own byte range, recompute every leaf from those
    /// bytes, and rebuild the chainhash. It is `merkle-audit` in miniature, and
    /// it is what catches a leaf that was pushed out of step with its line.
    /// Recompute a batch's leaves from the events bytes it names, through the
    /// same code `merkle-audit` uses. Pure -- it asserts nothing, so a tampered
    /// store yields different leaves rather than a panic.
    pub(crate) fn recompute_leaves(dir: &Path, host: &str, b: &BatchLine) -> Option<Vec<[u8; 32]>> {
        let raw = std::fs::read(events_path(dir, host)).ok()?;
        batch_leaves_from_events(&raw, b)
    }

    /// Chainhash of batch `id` as the events file stands now. Differs from the
    /// stored one exactly when the committed bytes have changed.
    pub(crate) fn recomputed_chainhash(dir: &Path, host: &str, id: usize) -> Option<String> {
        let batches = batch_lines(dir, host);
        let b = batches.get(id)?;
        Some(hex_string(&merkle::root(&recompute_leaves(dir, host, b)?)))
    }

    /// The strict form the happy-path tests use: recompute, and additionally
    /// assert every stored leaf matches. `merkle-audit` in miniature.
    pub(crate) fn verify_batch_against_bytes(dir: &Path, host: &str, b: &BatchLine) -> String {
        let Some(leaves) = recompute_leaves(dir, host, b) else {
            panic!("batch {} names a byte range that no longer reads", b.batch_id)
        };
        assert_eq!(leaves.len(), b.count as usize, "batch {} leaf count", b.batch_id);
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(
                Some(&hex_string(l)),
                b.leaves.get(i),
                "batch {} leaf {} does not match the stored leaf",
                b.batch_id,
                i
            );
        }
        hex_string(&merkle::root(&leaves))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_commits_to_the_bytes_it_wrote() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let k0 = [21u8; 32];
        enroll_for_test(&dir.0, "web-01", &k0);

        let mut prev = GENESIS_MAC.to_string();
        for b in 0..3u64 {
            let (body, next) = batch(&k0, b * 5 + 1, 5, &prev);
            prev = next;
            assert_eq!(post_batch(&app, "web-01", body).await, StatusCode::OK);
        }

        let batches = batch_lines(&dir.0, "web-01");
        assert_eq!(batches.len(), 3, "one batch line per accepted POST");

        let mut expect_prev = GENESIS_MAC.to_string();
        let mut expect_start = 0u64;
        for (i, b) in batches.iter().enumerate() {
            assert_eq!(b.v, 1);
            assert_eq!(b.batch_id, i as u64, "batch_id must be dense from 0");
            assert_eq!(b.host, "web-01");
            assert_eq!(b.count, 5);
            assert_eq!(b.seq_lo, i as u64 * 5 + 1);
            assert_eq!(b.seq_hi, i as u64 * 5 + 5);
            // Ranges are contiguous and non-overlapping.
            assert_eq!(b.byte_start, expect_start, "batch {} byte_start", i);
            assert!(b.byte_end > b.byte_start);
            expect_start = b.byte_end;
            // prev_chainhash chains, so deleting a whole batch line shows up.
            assert_eq!(b.prev_chainhash, expect_prev, "batch {} prev_chainhash", i);
            expect_prev = b.chainhash.clone();
            // And the commitment matches the bytes on disk.
            assert_eq!(
                verify_batch_against_bytes(&dir.0, "web-01", b),
                b.chainhash,
                "batch {} chainhash",
                i
            );
        }

        let events_len = std::fs::metadata(events_path(&dir.0, "web-01"))
            .unwrap_or_else(|e| panic!("events: {}", e))
            .len();
        assert_eq!(expect_start, events_len, "batches must cover the whole file");
    }

    /// An idempotent replay seals nothing.
    ///
    /// Every record is skipped by the `seq <= high_seq` check, so
    /// `pending_leaves` is empty and no second batch line is written. Easy to
    /// get wrong, and getting it wrong means a batch committing to zero bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replayed_batch_seals_nothing() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let k0 = [22u8; 32];
        enroll_for_test(&dir.0, "replay", &k0);

        let (body, _) = batch(&k0, 1, 4, GENESIS_MAC);
        assert_eq!(post_batch(&app, "replay", body.clone()).await, StatusCode::OK);
        assert_eq!(batch_lines(&dir.0, "replay").len(), 1);

        for _ in 0..3 {
            assert_eq!(post_batch(&app, "replay", body.clone()).await, StatusCode::OK);
        }
        assert_eq!(
            batch_lines(&dir.0, "replay").len(),
            1,
            "a replay wrote a second batch line"
        );
        assert_eq!(stored_lines(&dir.0, "replay").len(), 4);
    }

    /// A CHAIN_BREAK marker is a committed leaf, and provable.
    ///
    /// The marker is the most valuable line in the file. If it were left
    /// uncommitted, deleting it later would be invisible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_chain_break_marker_is_committed_and_provable() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let k0 = [23u8; 32];
        enroll_for_test(&dir.0, "broken", &k0);

        let (good, _) = batch(&k0, 1, 2, GENESIS_MAC);
        assert_eq!(post_batch(&app, "broken", good).await, StatusCode::OK);

        // seq 5 with a genesis prev_hash: a gap and a broken link.
        let (bad, _) = batch(&k0, 5, 1, GENESIS_MAC);
        assert_eq!(post_batch(&app, "broken", bad).await, StatusCode::CONFLICT);

        let batches = batch_lines(&dir.0, "broken");
        assert_eq!(batches.len(), 2);
        let Some(b) = batches.get(1) else { panic!("second batch") };
        // The marker plus the record it flagged.
        assert_eq!(b.count, 2, "the marker must be committed alongside the record");
        assert_eq!(verify_batch_against_bytes(&dir.0, "broken", b), b.chainhash);

        // The marker leaf is provable against the batch chainhash without K0.
        let leaves: Vec<[u8; 32]> = b
            .leaves
            .iter()
            .map(|h| unhex(h).unwrap_or_else(|| panic!("leaf hex {:?}", h)))
            .collect();
        let root = merkle::root(&leaves);
        assert_eq!(hex_string(&root), b.chainhash);
        for (i, leaf) in leaves.iter().enumerate() {
            let p = merkle::path(&leaves, i).unwrap_or_else(|| panic!("path {}", i));
            assert!(merkle::verify_path(*leaf, i, leaves.len(), &p, root));
        }
    }

    /// A state file written before Merkle batching existed still loads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pre_merkle_state_file_loads_and_starts_at_batch_zero() {
        let dir = temp_dir();
        let k0 = [24u8; 32];
        enroll_for_test(&dir.0, "old", &k0);

        // Exactly the shape the collector wrote before this change.
        let legacy = json!({
            "high_seq": 0, "high_epoch": 0, "last_mac": GENESIS_MAC,
            "last_seen": null, "breaks": 0, "segment": 0,
            "total_records": 0, "silent": false
        });
        write_atomic(
            &state_path(&dir.0, "old"),
            &serde_json::to_string_pretty(&legacy).unwrap_or_else(|e| panic!("{}", e)),
        )
        .unwrap_or_else(|e| panic!("{}", e));

        let app = Arc::new(App::new(dir.0.clone(), 8));
        let (body, _) = batch(&k0, 1, 3, GENESIS_MAC);
        assert_eq!(post_batch(&app, "old", body).await, StatusCode::OK);

        let batches = batch_lines(&dir.0, "old");
        assert_eq!(batches.len(), 1);
        let Some(b) = batches.first() else { panic!("batch") };
        assert_eq!(b.batch_id, 0, "a legacy state file must start at batch 0");
        assert_eq!(b.prev_chainhash, GENESIS_MAC);
    }

    /// Concurrent writers to one host produce disjoint, contiguous ranges and
    /// a dense batch_id sequence -- no two batches claim the same bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_batches_claim_disjoint_byte_ranges() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 32));
        let k0 = [25u8; 32];
        enroll_for_test(&dir.0, "racy", &k0);

        let mut tasks = Vec::new();
        for b in 0..8u64 {
            let app = Arc::clone(&app);
            let (body, _) = batch(&k0, b * 10 + 1, 10, GENESIS_MAC);
            tasks.push(tokio::spawn(async move { post_batch(&app, "racy", body).await }));
        }
        for t in tasks {
            t.await.expect("no panic");
        }

        let mut batches = batch_lines(&dir.0, "racy");
        batches.sort_by_key(|b| b.batch_id);
        for (i, b) in batches.iter().enumerate() {
            assert_eq!(b.batch_id, i as u64, "batch_id must be dense with no duplicates");
            assert_eq!(
                verify_batch_against_bytes(&dir.0, "racy", b),
                b.chainhash,
                "batch {} does not match its bytes",
                i
            );
        }
        // Ranges are contiguous end-to-start and therefore non-overlapping.
        let mut cursor = 0u64;
        for b in &batches {
            assert_eq!(b.byte_start, cursor, "batch {} overlaps or skips", b.batch_id);
            cursor = b.byte_end;
        }
    }

    /// The kill switch: with batching off, ingest works and seals nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn merkle_off_stores_records_and_writes_no_batches() {
        let dir = temp_dir();
        let app = Arc::new(App::with_merkle(dir.0.clone(), 8, false));
        let k0 = [26u8; 32];
        enroll_for_test(&dir.0, "plain", &k0);

        let (body, _) = batch(&k0, 1, 4, GENESIS_MAC);
        assert_eq!(post_batch(&app, "plain", body).await, StatusCode::OK);
        assert_eq!(stored_lines(&dir.0, "plain").len(), 4);
        assert!(!batches_path(&dir.0, "plain").exists());
    }

    /// The in-memory index survives a restart: rebuilt by scanning the files.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_index_is_rebuilt_from_disk_at_startup() {
        let dir = temp_dir();
        let k0 = [27u8; 32];
        enroll_for_test(&dir.0, "restart", &k0);

        {
            let app = Arc::new(App::new(dir.0.clone(), 8));
            let mut prev = GENESIS_MAC.to_string();
            for b in 0..3u64 {
                let (body, next) = batch(&k0, b * 4 + 1, 4, &prev);
                prev = next;
                assert_eq!(post_batch(&app, "restart", body).await, StatusCode::OK);
            }
        }

        // Fresh process, same data dir.
        let reborn = Arc::new(App::new(dir.0.clone(), 8));
        let index = reborn.merkle.lock().await;
        let Some(entries) = index.batches.get("restart") else {
            panic!("the index did not survive the restart")
        };
        assert_eq!(entries.len(), 3);
        let on_disk = batch_lines(&dir.0, "restart");
        for (i, e) in entries.iter().enumerate() {
            let Some(b) = on_disk.get(i) else { panic!("batch {}", i) };
            assert_eq!(e.batch_id, b.batch_id);
            assert_eq!(e.byte_start, b.byte_start);
            assert_eq!(e.byte_end, b.byte_end);
            assert_eq!(e.count, b.count);
        }
        // line_offsets point at real lines.
        let raw = std::fs::read(batches_path(&dir.0, "restart")).unwrap_or_else(|e| panic!("{}", e));
        for e in entries.iter() {
            let Some(rest) = raw.get(e.line_offset as usize..) else {
                panic!("line_offset {} is past the file", e.line_offset)
            };
            assert_eq!(rest.first(), Some(&b'{'), "line_offset is not at a line start");
        }
    }
}

// ---------------------------------------------------------
// Tamper detection (server.md acceptance tests)
// ---------------------------------------------------------
//
// The point of committing to bytes is that changing them afterwards is
// detectable by anyone, without K0. These drive that directly: edit the store
// behind the collector's back and confirm the commitment no longer matches.
#[cfg(test)]
mod tamper_tests {
    use super::concurrency_tests::*;
    use super::merkle_batch_tests::*;
    use super::*;

    async fn one_batch(dir: &Path, host: &str, k0: &[u8; 32]) {
        let app = Arc::new(App::new(dir.to_path_buf(), 8));
        enroll_for_test(dir, host, k0);
        let (body, _) = batch(k0, 1, 6, GENESIS_MAC);
        assert_eq!(post_batch(&app, host, body).await, StatusCode::OK);
    }

    /// Editing one byte of a stored record breaks its batch's chainhash.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn editing_one_byte_of_a_record_breaks_the_commitment() {
        let dir = temp_dir();
        let k0 = [31u8; 32];
        one_batch(&dir.0, "victim", &k0).await;

        let path = events_path(&dir.0, "victim");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let sealed = recomputed_chainhash(&dir.0, "victim", 0);
        assert!(sealed.is_some(), "the untampered store recomputes cleanly");

        // Rename the process in one record. Everything else is untouched, and
        // the line is still valid JSON -- only the committed bytes differ.
        let after = before.replacen("\"process_name\":\"bash\"", "\"process_name\":\"bosh\"", 1);
        assert_ne!(after, before, "the tamper must actually change the file");
        assert_eq!(after.len(), before.len(), "same length, so byte ranges still line up");
        std::fs::write(&path, &after).unwrap_or_else(|e| panic!("{}", e));

        assert_ne!(
            recomputed_chainhash(&dir.0, "victim", 0),
            sealed,
            "a tampered record recomputed to the same chainhash"
        );
    }

    /// Deleting a whole line breaks it too -- the leaf count no longer matches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deleting_a_line_breaks_the_commitment() {
        let dir = temp_dir();
        let k0 = [32u8; 32];
        one_batch(&dir.0, "gap", &k0).await;

        let path = events_path(&dir.0, "gap");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let kept: Vec<&str> = before.lines().skip(1).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap_or_else(|e| panic!("{}", e));

        // The batch names a byte range; a deleted line means the range no
        // longer holds the committed count.
        let batches = batch_lines(&dir.0, "gap");
        let Some(b) = batches.first() else { panic!("batch") };
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}", e));
        let recomputed = raw
            .get(b.byte_start as usize..b.byte_end as usize)
            .map(|slice| String::from_utf8_lossy(slice).lines().count());
        assert_ne!(
            recomputed,
            Some(b.count as usize),
            "a deleted line left the committed count intact"
        );
    }

    /// Deleting a batch line breaks prev_chainhash continuity, which is visible
    /// without ever reaching for the on-chain root.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deleting_a_batch_line_breaks_the_batch_chain() {
        let dir = temp_dir();
        let k0 = [33u8; 32];
        enroll_for_test(&dir.0, "chained", &k0);
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let mut prev = GENESIS_MAC.to_string();
        for b in 0..3u64 {
            let (body, next) = batch(&k0, b * 3 + 1, 3, &prev);
            prev = next;
            assert_eq!(post_batch(&app, "chained", body).await, StatusCode::OK);
        }

        let path = batches_path(&dir.0, "chained");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let kept: Vec<&str> = before
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap_or_else(|e| panic!("{}", e));

        let remaining = batch_lines(&dir.0, "chained");
        assert_eq!(remaining.len(), 2);
        let (Some(first), Some(second)) = (remaining.first(), remaining.get(1)) else {
            panic!("two batches")
        };
        assert_ne!(
            second.prev_chainhash, first.chainhash,
            "removing a batch line left the chain looking intact"
        );
    }
}


// ---------------------------------------------------------
// Root sealing (server.md 2.7, step 7)
// ---------------------------------------------------------
#[cfg(test)]
mod root_tests {
    use super::concurrency_tests::*;
    use super::*;

    /// Seal immediately: one pending batch is already >= the trigger.
    const NOW: usize = 1;
    /// Never on the count trigger, so only the interval can fire.
    const NEVER: usize = usize::MAX;

    fn root_lines(dir: &Path) -> Vec<RootLine> {
        let raw = std::fs::read_to_string(roots_path(dir)).unwrap_or_default();
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("root line {:?}: {}", l, e)))
            .collect()
    }

    async fn ingest_one(app: &Arc<App>, host: &str, k0: &[u8; 32], from_seq: u64, prev: &str) -> String {
        let (body, next) = batch(k0, from_seq, 3, prev);
        assert_eq!(post_batch(app, host, body).await, StatusCode::OK);
        next
    }

    /// A quiet fleet must seal nothing. An empty root is a blockchain
    /// transaction that commits to no records at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_empty_fleet_seals_nothing() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        assert!(seal_once(&app, 0, NOW).await.is_none());
        assert!(!roots_path(&dir.0).exists(), "no pending batches, no root file");
    }

    /// Both triggers, and only when they are due.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_seals_on_the_count_trigger_and_on_the_interval() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let k0 = [41u8; 32];
        enroll_for_test(&dir.0, "web-01", &k0);

        let prev = ingest_one(&app, "web-01", &k0, 1, GENESIS_MAC).await;

        // Neither trigger: one pending batch, a count threshold it cannot
        // reach, and an interval that has not elapsed.
        assert!(seal_once(&app, 3600, NEVER).await.is_none());
        assert_eq!(app.merkle.lock().await.pending.len(), 1);

        // Count trigger.
        assert_eq!(seal_once(&app, 3600, NOW).await, Some(0));
        assert!(app.merkle.lock().await.pending.is_empty());

        // Interval trigger: a zero interval is always elapsed.
        ingest_one(&app, "web-01", &k0, 4, &prev).await;
        assert_eq!(seal_once(&app, 0, NEVER).await, Some(1));

        let roots = root_lines(&dir.0);
        assert_eq!(roots.len(), 2, "one root per seal, and only when due");
    }

    /// prev_root chains roots the way prev_chainhash chains batches, so a
    /// deleted root line is visible without consulting the chain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roots_chain_through_prev_root() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let k0 = [42u8; 32];
        enroll_for_test(&dir.0, "web-01", &k0);

        let mut prev = GENESIS_MAC.to_string();
        for i in 0..3u64 {
            prev = ingest_one(&app, "web-01", &k0, i * 3 + 1, &prev).await;
            assert_eq!(seal_once(&app, 0, NOW).await, Some(i));
        }

        let roots = root_lines(&dir.0);
        assert_eq!(roots.len(), 3);
        let mut expect = GENESIS_MAC.to_string();
        for (i, r) in roots.iter().enumerate() {
            assert_eq!(r.root_id, i as u64, "root ids are dense from 0");
            assert_eq!(r.prev_root, expect, "root {} does not chain", i);
            expect = r.root.clone();
        }
    }

    /// The level-2 leaf order is part of the format: hosts ascending, batches
    /// ascending within a host. A verifier that sorts differently computes a
    /// different root and every proof fails, so the written order is pinned
    /// here and the root is rebuilt from it independently.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_is_built_in_canonical_order() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let k0 = [43u8; 32];
        // Enrolled and ingested in reverse alphabetical order on purpose.
        for host in ["z-host", "m-host", "a-host"] {
            enroll_for_test(&dir.0, host, &k0);
            let mut prev = GENESIS_MAC.to_string();
            for b in 0..2u64 {
                prev = ingest_one(&app, host, &k0, b * 3 + 1, &prev).await;
            }
        }
        assert_eq!(seal_once(&app, 0, NOW).await, Some(0));

        let roots = root_lines(&dir.0);
        let Some(r) = roots.first() else { panic!("one root") };
        let hosts: Vec<&str> = r.covers.iter().map(|c| c.host.as_str()).collect();
        assert_eq!(hosts, vec!["a-host", "m-host", "z-host"]);
        assert_eq!(r.leaf_count, 6);
        for c in &r.covers {
            assert_eq!((c.batch_lo, c.batch_hi), (0, 1));
            assert_eq!(c.chainhashes.len(), 2);
        }

        // Rebuilt from the line alone, as a third party would.
        let mut leaves = Vec::new();
        for c in &r.covers {
            for (i, h) in c.chainhashes.iter().enumerate() {
                let chain = unhex(h).unwrap_or_else(|| panic!("chainhash hex"));
                leaves.push(merkle::batch_leaf(&c.host, c.batch_lo + i as u64, &chain));
            }
        }
        assert_eq!(hex_string(&merkle::root(&leaves)), r.root);

        // And every leaf is provable against the root without K0.
        let root = merkle::root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let path = merkle::path(&leaves, i).unwrap_or_else(|| panic!("path {}", i));
            assert!(merkle::verify_path(*leaf, i, leaves.len(), &path, root));
        }
    }

    /// Sealing while agents keep POSTing must lose no batch and double-count
    /// none. The sealer releases the index lock across its fsync, so anything
    /// ingest queues meanwhile has to survive into the next root.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sealing_under_concurrent_ingest_loses_no_batch() {
        let dir = temp_dir();
        let app = Arc::new(App::new(dir.0.clone(), 32));
        let k0 = [44u8; 32];

        const HOSTS: u64 = 8;
        const BATCHES: u64 = 6;
        for h in 0..HOSTS {
            enroll_for_test(&dir.0, &format!("host-{:02}", h), &k0);
        }

        let sealer = {
            let app = Arc::clone(&app);
            tokio::spawn(async move {
                for _ in 0..40 {
                    seal_once(&app, 0, NOW).await;
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
        };

        let mut posting = Vec::new();
        for h in 0..HOSTS {
            let app = Arc::clone(&app);
            posting.push(tokio::spawn(async move {
                let host = format!("host-{:02}", h);
                let mut prev = GENESIS_MAC.to_string();
                for b in 0..BATCHES {
                    let (body, next) = batch(&k0, b * 3 + 1, 3, &prev);
                    prev = next;
                    assert_eq!(post_batch(&app, &host, body).await, StatusCode::OK);
                }
            }));
        }
        let guarded = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            for t in posting {
                t.await.unwrap_or_else(|e| panic!("poster: {}", e));
            }
            sealer.await.unwrap_or_else(|e| panic!("sealer: {}", e));
        })
        .await;
        assert!(guarded.is_ok(), "a lock inversion would hang here");

        // Drain whatever was still queued when the sealer stopped.
        while seal_once(&app, 0, NOW).await.is_some() {}
        assert!(app.merkle.lock().await.pending.is_empty());

        let mut seen: HashMap<String, Vec<u64>> = HashMap::new();
        for r in root_lines(&dir.0) {
            for c in &r.covers {
                for id in c.batch_lo..=c.batch_hi {
                    seen.entry(c.host.clone()).or_default().push(id);
                }
            }
        }
        for h in 0..HOSTS {
            let host = format!("host-{:02}", h);
            let mut ids = seen.remove(&host).unwrap_or_default();
            ids.sort_unstable();
            let before = ids.len();
            ids.dedup();
            assert_eq!(before, ids.len(), "{} has a batch in two roots", host);
            assert_eq!(
                ids,
                (0..BATCHES).collect::<Vec<u64>>(),
                "{} is missing a batch from every root",
                host
            );
        }
    }

    /// The pending queue survives a restart: a batch sealed but not yet rooted
    /// before the process died is still rooted after it comes back, and one
    /// already covered is not rooted twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_batches_are_rebuilt_from_disk_at_startup() {
        let dir = temp_dir();
        let k0 = [45u8; 32];
        enroll_for_test(&dir.0, "web-01", &k0);

        let prev = {
            let app = Arc::new(App::new(dir.0.clone(), 8));
            let prev = ingest_one(&app, "web-01", &k0, 1, GENESIS_MAC).await;
            assert_eq!(seal_once(&app, 0, NOW).await, Some(0));
            // Sealed but not rooted when the process goes away.
            ingest_one(&app, "web-01", &k0, 4, &prev).await
        };

        let restarted = Arc::new(App::new(dir.0.clone(), 8));
        {
            let index = restarted.merkle.lock().await;
            assert_eq!(index.next_root_id, 1, "root ids continue where they left off");
            assert_eq!(index.pending.len(), 1, "batch 0 is rooted, batch 1 is not");
            let Some(p) = index.pending.first() else { panic!("pending") };
            assert_eq!((p.host.as_str(), p.batch_id), ("web-01", 1));
        }

        let _ = ingest_one(&restarted, "web-01", &k0, 7, &prev).await;
        assert_eq!(seal_once(&restarted, 0, NOW).await, Some(1));

        let roots = root_lines(&dir.0);
        assert_eq!(roots.len(), 2);
        let Some(second) = roots.get(1) else { panic!("second root") };
        let Some(cover) = second.covers.first() else { panic!("cover") };
        assert_eq!(
            (cover.batch_lo, cover.batch_hi),
            (1, 2),
            "the batch sealed before the restart must still be rooted, exactly once"
        );
        assert_eq!(audit(&dir.0, None).divergences, Vec::<String>::new());
    }
}

// ---------------------------------------------------------
// merkle-audit (server.md 2.9, step 6)
// ---------------------------------------------------------
#[cfg(test)]
mod audit_tests {
    use super::concurrency_tests::*;
    use super::merkle_batch_tests::*;
    use super::*;

    /// `n` batches for one host, then a root over them.
    async fn store(dir: &Path, host: &str, k0: &[u8; 32], n: u64) {
        let app = Arc::new(App::new(dir.to_path_buf(), 8));
        enroll_for_test(dir, host, k0);
        let mut prev = GENESIS_MAC.to_string();
        for b in 0..n {
            let (body, next) = batch(k0, b * 4 + 1, 4, &prev);
            prev = next;
            assert_eq!(post_batch(&app, host, body).await, StatusCode::OK);
        }
        assert!(seal_once(&app, 0, 1).await.is_some(), "the batches must root");
    }

    fn assert_intact(dir: &Path) {
        let report = audit(dir, None);
        assert_eq!(report.divergences, Vec::<String>::new());
    }

    /// The finding must name the thing that broke, not merely be non-empty --
    /// an auditor reads this output and acts on it.
    fn assert_reports(dir: &Path, needle: &str) {
        let report = audit(dir, None);
        assert!(
            report.divergences.iter().any(|d| d.contains(needle)),
            "no divergence mentioning {:?}; got {:#?}",
            needle,
            report.divergences
        );
    }

    /// Real data, untouched: every chainhash and every root recomputes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_untouched_store_audits_as_intact() {
        let dir = temp_dir();
        let k0 = [51u8; 32];
        store(&dir.0, "web-01", &k0, 3).await;
        store(&dir.0, "db-02", &k0, 2).await;

        let report = audit(&dir.0, None);
        assert_eq!(report.divergences, Vec::<String>::new());
        assert_eq!(report.roots, 2);
        assert_eq!(
            report.rows,
            vec![
                ("db-02".to_string(), 2, 8),
                ("web-01".to_string(), 3, 12),
            ]
        );
        // Auditing one host still audits every root -- a root recomputes from
        // its own line and needs no host's files.
        assert_eq!(audit(&dir.0, Some("web-01")).roots, 2);
    }

    /// Editing one byte of a record must be reported, not smoothed over.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn editing_one_byte_is_reported() {
        let dir = temp_dir();
        let k0 = [52u8; 32];
        store(&dir.0, "victim", &k0, 2).await;
        assert_intact(&dir.0);

        let path = events_path(&dir.0, "victim");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let after = before.replacen("\"process_name\":\"bash\"", "\"process_name\":\"bosh\"", 1);
        assert_eq!(after.len(), before.len(), "same length keeps byte ranges aligned");
        std::fs::write(&path, &after).unwrap_or_else(|e| panic!("{}", e));

        assert_reports(&dir.0, "leaf 0 recomputes to");
        assert_reports(&dir.0, "chainhash recomputes to");
    }

    /// A deleted record line shortens the committed range.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_line_is_reported() {
        let dir = temp_dir();
        let k0 = [53u8; 32];
        store(&dir.0, "gap", &k0, 2).await;

        let path = events_path(&dir.0, "gap");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let kept: Vec<&str> = before.lines().skip(1).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap_or_else(|e| panic!("{}", e));

        assert!(!audit(&dir.0, Some("gap")).divergences.is_empty());
    }

    /// A deleted batch line breaks prev_chainhash continuity, and the root
    /// that covered it now names a batch that is not there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_batch_line_is_reported() {
        let dir = temp_dir();
        let k0 = [54u8; 32];
        store(&dir.0, "chained", &k0, 3).await;

        let path = batches_path(&dir.0, "chained");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let kept: Vec<&str> = before
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap_or_else(|e| panic!("{}", e));

        assert_reports(&dir.0, "prev_chainhash");
        assert_reports(&dir.0, "batch ids are not dense");
    }

    /// A deleted root line breaks prev_root continuity, and every batch it
    /// covered is left with no covering root. Report it loudly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_root_line_is_reported() {
        let dir = temp_dir();
        let k0 = [55u8; 32];
        enroll_for_test(&dir.0, "web-01", &k0);
        let app = Arc::new(App::new(dir.0.clone(), 8));
        let mut prev = GENESIS_MAC.to_string();
        for b in 0..3u64 {
            let (body, next) = batch(&k0, b * 3 + 1, 3, &prev);
            prev = next;
            assert_eq!(post_batch(&app, "web-01", body).await, StatusCode::OK);
            assert_eq!(seal_once(&app, 0, 1).await, Some(b));
        }
        assert_intact(&dir.0);

        let path = roots_path(&dir.0);
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let kept: Vec<&str> = before
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap_or_else(|e| panic!("{}", e));

        assert_reports(&dir.0, "root ids are not dense");
        assert_reports(&dir.0, "prev_root");
    }

    /// Rewriting a root's own hash is caught by recomputation, even though
    /// every batch it covers is untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewritten_root_is_reported() {
        let dir = temp_dir();
        let k0 = [56u8; 32];
        store(&dir.0, "web-01", &k0, 2).await;

        let path = roots_path(&dir.0);
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let mut r: RootLine = serde_json::from_str(before.trim()).unwrap_or_else(|e| panic!("{}", e));
        r.root = "00".repeat(32);
        let mut line = serde_json::to_string(&r).unwrap_or_else(|e| panic!("{}", e));
        line.push('\n');
        std::fs::write(&path, line).unwrap_or_else(|e| panic!("{}", e));

        assert_reports(&dir.0, "recomputes to");
    }

    /// Swapping a chainhash inside a root is caught two ways: the root no
    /// longer recomputes, and the batch line disagrees with what the root says
    /// it sealed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_swapped_chainhash_in_a_root_is_reported() {
        let dir = temp_dir();
        let k0 = [57u8; 32];
        store(&dir.0, "web-01", &k0, 2).await;

        let path = roots_path(&dir.0);
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let mut r: RootLine = serde_json::from_str(before.trim()).unwrap_or_else(|e| panic!("{}", e));
        let Some(cover) = r.covers.first_mut() else { panic!("cover") };
        cover.chainhashes.swap(0, 1);
        let mut line = serde_json::to_string(&r).unwrap_or_else(|e| panic!("{}", e));
        line.push('\n');
        std::fs::write(&path, line).unwrap_or_else(|e| panic!("{}", e));

        assert_reports(&dir.0, "but that batch line says");
        assert_reports(&dir.0, "recomputes to");
    }

    /// A CHAIN_BREAK marker is a committed leaf, so it audits like any other
    /// line -- deleting it later would otherwise be invisible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_committed_marker_audits_and_cannot_be_removed_quietly() {
        let dir = temp_dir();
        let k0 = [58u8; 32];
        enroll_for_test(&dir.0, "broken", &k0);
        let app = Arc::new(App::new(dir.0.clone(), 8));

        let (body, _) = batch(&k0, 1, 2, GENESIS_MAC);
        assert_eq!(post_batch(&app, "broken", body).await, StatusCode::OK);
        // A record that does not chain: the collector writes a CHAIN_BREAK
        // marker before it, and both are committed.
        let forged = seal_one(&k0, 3, &"aa".repeat(32));
        let body = serde_json::to_string(&forged).unwrap_or_else(|e| panic!("{}", e)) + "\n";
        assert_eq!(post_batch(&app, "broken", body).await, StatusCode::CONFLICT);
        assert_eq!(seal_once(&app, 0, 1).await, Some(0));
        assert_intact(&dir.0);

        let batches = batch_lines(&dir.0, "broken");
        let Some(b) = batches.get(1) else { panic!("second batch") };
        assert_eq!(b.count, 2, "the marker is committed alongside the record");

        // Remove the marker line and nothing else.
        let path = events_path(&dir.0, "broken");
        let before = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}", e));
        let kept: Vec<&str> = before
            .lines()
            .filter(|l| !l.contains("CHAIN_BREAK"))
            .collect();
        assert_eq!(kept.len(), before.lines().count() - 1, "one marker removed");
        std::fs::write(&path, kept.join("\n") + "\n").unwrap_or_else(|e| panic!("{}", e));

        assert!(!audit(&dir.0, None).divergences.is_empty());
    }
}
