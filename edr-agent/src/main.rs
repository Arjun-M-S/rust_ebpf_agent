use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use chrono::{DateTime, Local};
use clap::Parser;
use edr_agent_common::record::{record_mac, verify_record, AgentLog, GENESIS_MAC};
use edr_agent_common::ProcessEvent;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

mod shipper;

// ---------------------------------------------------------
// Paths and limits
// ---------------------------------------------------------
// NOW-1: /tmp is world-writable, so a root-owned agent creating a file there is
// an arbitrary-append primitive for anyone who pre-creates the path as a
// symlink. A dedicated 0700 directory removes the race entirely.
const WAL_DIR: &str = "/var/log/edr";
const WAL_PATH: &str = "/var/log/edr/edr.wal";
const WAL_ARCHIVE_PATH: &str = "/var/log/edr/edr.wal.1";
const STATE_PATH: &str = "/var/log/edr/edr.state";
const STATE_TMP_PATH: &str = "/var/log/edr/edr.state.tmp";
const PIN_PATH: &str = "/sys/fs/bpf/edr_events";
const CURSOR_PATH: &str = "/var/log/edr/edr.cursor";

/// NOW-14: hard ceiling so a flood of execs cannot take the host down by
/// filling the filesystem. One archive generation is kept.
const MAX_WAL_BYTES: u64 = 256 * 1024 * 1024;

/// Section 8: the sealing key evolves on a timer, not per record. Per-record
/// evolution means a state write per event; a fixed epoch bounds how much an
/// attacker who lands at time t can backdate, at a fraction of the I/O. This
/// is the same trade journald's FSS makes.
const EPOCH_SECS: u64 = 60;

const FLUSH_INTERVAL_MS: u64 = 200;
const HEALTH_INTERVAL_SECS: u64 = 30;
const CHANNEL_CAPACITY: usize = 4096;

// The record format, the payload encoding and the key schedule all live in
// edr-agent-common::record so the collector verifies exactly what the agent
// sealed. Do not reintroduce a local copy.

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// Base URL of the collector, e.g. https://collector.example.net. Omit and
    /// the agent runs local-only: records are still sealed and written to the
    /// WAL, but nothing leaves the host, and tail truncation stays undetectable
    /// because nothing off-box remembers the high-water mark (STO-4).
    #[clap(long)]
    collector_url: Option<String>,

    /// Identity presented to the collector. Defaults to the kernel hostname.
    #[clap(long)]
    host_id: Option<String>,

    /// Records per shipping batch. With --ship-interval this is also the
    /// catch-up rate limit: the drain ceiling is batch/interval, which is what
    /// stops a backlog from saturating the uplink after an outage.
    #[clap(long, default_value_t = 500)]
    ship_batch: usize,

    /// Seconds between shipping attempts.
    #[clap(long, default_value_t = 5)]
    ship_interval: u64,
}

// ---------------------------------------------------------
// 2. Forward-secure sealing
// ---------------------------------------------------------
// NOW-4: the previous construction was an unkeyed SHA256 chain over public
// fields. A root attacker edits a record and recomputes every hash after it,
// because nothing secret is involved. Adding a key is not enough on its own
// either, since root can read a static key out of memory or off disk.
//
// The fix is a key that moves forward and cannot move back:
//
//     MAC_i   = HMAC(K_epoch, payload_i || MAC_{i-1})
//     K_{n+1} = SHA256(K_n)          <- one way
//     erase K_n                      <- the step that does the work
//
// An attacker who lands during epoch n gets K_n and nothing before it, so every
// record written in an earlier epoch is unforgeable to them. They own the
// machine; they still cannot rewrite how they got in.
//
// This holds only if K0 is escrowed off the box. It is printed once, at first
// start, and never written anywhere it can be recovered from afterwards.

#[derive(Serialize, Deserialize)]
struct PersistedState {
    key: String,
    epoch: u64,
    seq: u64,
    last_mac: String,
}

struct Sealer {
    key: [u8; 32],
    epoch: u64,
    seq: u64,
    last_mac: String,
    next_evolve: tokio::time::Instant,
}

impl Sealer {
    fn new(key: [u8; 32], epoch: u64, seq: u64, last_mac: String) -> Self {
        Self {
            key,
            epoch,
            seq,
            last_mac,
            next_evolve: tokio::time::Instant::now() + Duration::from_secs(EPOCH_SECS),
        }
    }

    /// Advance to the next key generation and destroy the current one.
    ///
    /// The old key is overwritten in place rather than dropped, so it does not
    /// linger in a freed allocation. This is best effort: the compiler may
    /// still elide it, and a key that has already been paged out or captured in
    /// a core dump is beyond reach. mlock and a TPM are the real answers.
    fn evolve(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.key);
        let next = hasher.finalize();
        for b in self.key.iter_mut() {
            *b = 0;
        }
        self.key.copy_from_slice(&next);
        self.epoch += 1;
    }

    fn seal(&mut self, log: &mut AgentLog) {
        self.seq += 1;
        log.seq = self.seq;
        log.epoch = self.epoch;
        log.prev_hash = self.last_mac.clone();

        let tag = record_mac(&self.key, log);
        log.hash = tag.clone();
        self.last_mac = tag;
    }

    fn snapshot(&self) -> PersistedState {
        PersistedState {
            key: hex::encode(self.key),
            epoch: self.epoch,
            seq: self.seq,
            last_mac: self.last_mac.clone(),
        }
    }
}

fn serialize_record(log: &AgentLog) -> Option<String> {
    match serde_json::to_string(log) {
        Ok(j) => Some(j),
        Err(e) => {
            eprintln!("CRITICAL: could not serialize record seq={}: {}", log.seq, e);
            None
        }
    }
}

async fn persist_state(state: &PersistedState) {
    let json = match serde_json::to_string(state) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("CRITICAL: could not serialize seal state: {}", e);
            return;
        }
    };

    // Write-then-rename so a crash mid-write cannot leave a truncated key file,
    // which would strand the chain with no way to continue it.
    let write = || -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(STATE_TMP_PATH)?;
        use std::io::Write;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        fs::rename(STATE_TMP_PATH, STATE_PATH)
    };

    if let Err(e) = write() {
        eprintln!("CRITICAL: could not persist seal state: {}", e);
    }
}

fn load_state() -> Option<PersistedState> {
    let raw = fs::read_to_string(STATE_PATH).ok()?;
    serde_json::from_str(&raw).ok()
}

// ---------------------------------------------------------
// 3. Secure WAL setup
// ---------------------------------------------------------
/// Create the log directory such that only we can write to it.
///
/// AGT-6: a group- or world-writable directory in the path of a file a root
/// process opens is a privilege escalation, not an untidiness. Checked at
/// startup rather than assumed from the installer.
fn prepare_wal_dir() -> Result<(), anyhow::Error> {
    // Inspect before touching anything. create_dir_all and set_permissions both
    // follow symlinks, so calling them first on an attacker-planted link would
    // chmod 0700 whatever it points at -- the same class of bug this function
    // exists to close, moved up one level to the directory.
    match fs::symlink_metadata(WAL_DIR) {
        Ok(md) if md.file_type().is_symlink() => {
            anyhow::bail!(
                "{} is a symlink. Refusing to start: following it would write the \
                 audit log somewhere chosen by whoever created it.",
                WAL_DIR
            );
        }
        Ok(md) if !md.is_dir() => {
            anyhow::bail!("{} exists and is not a directory; refusing to start", WAL_DIR);
        }
        Ok(md) => {
            if md.mode() & 0o022 != 0 {
                anyhow::bail!(
                    "{} is group- or world-writable (mode {:o}). Someone pre-created it. \
                     Refusing to start.",
                    WAL_DIR,
                    md.mode() & 0o777
                );
            }
            if md.uid() != 0 {
                eprintln!(
                    "WARNING: {} is owned by uid {}, not root. Anyone with that uid can \
                     tamper with the log directory.",
                    WAL_DIR,
                    md.uid()
                );
            }
        }
        Err(_) => {
            // Does not exist yet. create_dir_all is safe here because there is
            // nothing at the path to follow.
            fs::create_dir_all(WAL_DIR)?;
        }
    }

    fs::set_permissions(WAL_DIR, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Open the WAL safely and take an exclusive lock on it.
///
/// NOW-1: O_NOFOLLOW defeats the symlink attack on the final component, and the
/// nlink check defeats its sibling, the hardlink attack, which O_NOFOLLOW does
/// not cover.
///
/// NOW-10: the flock is what stops a second agent instance. Two processes
/// appending with independent chain state interleave their records and destroy
/// the chain, which an attacker can trigger deliberately just by starting
/// another copy. Failing to start is the correct outcome; a corrupted chain is
/// indistinguishable from tampering.
fn open_wal_locked(path: &str) -> Result<(std::fs::File, u64), anyhow::Error> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    let md = file.metadata()?;
    if !md.is_file() {
        anyhow::bail!("{} is not a regular file; refusing to write to it", path);
    }
    if md.nlink() != 1 {
        anyhow::bail!(
            "{} has {} hard links; another name for this inode exists. Refusing to start.",
            path,
            md.nlink()
        );
    }

    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        anyhow::bail!(
            "another edr-agent instance already holds the lock on {}. \
             Refusing to start: two writers would corrupt the hash chain.",
            path
        );
    }

    Ok((file, md.len()))
}

// ---------------------------------------------------------
// 4. Decoding
// ---------------------------------------------------------
/// NOW-11: Linux permits any byte except NUL and '/' in a filename. Decoding a
/// non-UTF-8 name to a single "<unknown>" placeholder made every such process
/// look identical and silently defeated every name-based rule at zero cost to
/// the attacker. The raw bytes are preserved as hex instead, and the condition
/// is itself reported, because no legitimate system binary has a name that
/// fails to decode.
fn decode_name(raw: &[u8]) -> (String, bool) {
    let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    let bytes = &raw[..len];
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (format!("hex:{}", hex::encode(bytes)), true),
    }
}

/// SEN-5: the path in the log names a file that may have been replaced or
/// renamed since the exec. dev:inode:mtime identifies what actually ran.
///
/// Best effort by nature: short-lived processes are gone before we look. Only
/// attempted for events already scored above INFO, so the per-event syscall
/// cost stays off the common path.
fn binary_identity(pid: u32) -> String {
    let path = format!("/proc/{}/exe", pid);
    match fs::metadata(&path) {
        Ok(md) => format!("{}:{}:{}", md.dev(), md.ino(), md.mtime()),
        Err(_) => String::new(),
    }
}

/// Linux caps pids at 2^22 even with pid_max raised to its ceiling.
const PID_MAX_CEILING: u32 = 4_194_304;

fn monotonic_now_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// SEN-6: anything written into the pinned perf array arrives on this path
/// indistinguishable from a genuine tracepoint hit, and the agent then seals it
/// as authentic. Forged records inside a tamper-evident log, signed by the
/// defender, are worse than no log at all.
///
/// The pin is chmod 0600, which closes the open-to-all case. This is the second
/// layer: every field the kernel probe controls is checked for a value the
/// probe could not have produced.
///
/// HONEST LIMIT: this catches sloppy injection, not careful injection. An
/// attacker who reads the probe source can craft values that pass every check
/// here, because the checks can only test what a real event looks like and a
/// forgery can be made to look real. It raises the cost and makes casual
/// injection noisy. It does not make the pinned map safe to expose, and it is
/// not a substitute for the collector noticing that a chain contains records
/// the host had no business producing.
fn implausible(ev: &ProcessEvent, now_ns: u64) -> Option<&'static str> {
    if ev.pid == 0 || ev.pid > PID_MAX_CEILING {
        return Some("pid outside the kernel's possible range");
    }
    if ev.ppid > PID_MAX_CEILING {
        return Some("ppid outside the kernel's possible range");
    }
    if ev.cmd[0] == 0 {
        return Some("empty process name; a real exec always has a comm");
    }
    if ev.ktime_ns == 0 {
        return Some("zero kernel timestamp");
    }
    // One second of slack covers scheduling between the kernel stamp and here.
    if ev.ktime_ns > now_ns.saturating_add(1_000_000_000) {
        return Some("kernel timestamp is in the future");
    }
    // The probe always zeroes this. An injector filling the struct from a
    // template usually does not.
    if ev._pad != 0 {
        return Some("reserved padding is non-zero");
    }
    None
}

// ---------------------------------------------------------
// 5. Scoring
// ---------------------------------------------------------
/// DISC-1 inverted: the agent cannot hide from root. The process name, the pin
/// path and the log path are all discoverable with one command, and trying to
/// conceal them is effort spent on something root defeats anyway.
///
/// So the reconnaissance becomes the detection. An attacker's cheapest and most
/// reliable first move is to find out what is watching them, and these are the
/// tools they reach for. This is a better position than invisibility because it
/// does not depend on the attacker failing to look.
const TAMPER_TOOLS: &[&str] = &[
    "bpftool", "chattr", "shred", "srm", "wipe", "auditctl", "setenforce",
    "logrotate", "journalctl",
];

/// Anti-forensics and defence evasion.
const DESTRUCTIVE: &[&str] = &["dd", "truncate"];

/// Services that should never be the parent of an interactive shell. A shell
/// here means the service was exploited into spawning one.
const NETWORK_SERVICES: &[&str] = &[
    "nginx", "apache2", "httpd", "php-fpm", "mysqld", "postgres", "tomcat",
    "node", "redis-server",
];

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "python3", "python", "perl", "ruby"];

/// Local privilege escalation surface.
const PRIVESC: &[&str] = &["pkexec", "sudo", "su", "doas"];

/// Reconnaissance tooling.
const RECON: &[&str] = &["nmap", "masscan", "tcpdump", "nc", "ncat", "socat"];

fn severity_for(process_name: &str, parent: &str, undecodable: bool) -> &'static str {
    if undecodable {
        // A name that is not valid UTF-8 is itself the finding.
        return "HIGH";
    }
    if TAMPER_TOOLS.contains(&process_name) {
        return "CRITICAL";
    }
    if NETWORK_SERVICES.contains(&parent) && SHELLS.contains(&process_name) {
        return "CRITICAL";
    }
    if DESTRUCTIVE.contains(&process_name) || PRIVESC.contains(&process_name) {
        return "HIGH";
    }
    if RECON.contains(&process_name) {
        return "MEDIUM";
    }
    "INFO"
}

// ---------------------------------------------------------
// 6. Clock
// ---------------------------------------------------------
/// Wall-clock time corresponding to kernel monotonic zero, measured once.
///
/// bpf_ktime_get_ns is CLOCK_MONOTONIC, so event time is `boot + ktime`. This
/// keeps ordering correct under load. It does not defend against NOW-7, where
/// root moves the system clock: only a collector applying its own receipt time
/// can do that. What it fixes is NOW-12, where a flooded pipeline made events
/// appear to have happened whenever the agent got round to them.
fn monotonic_epoch() -> DateTime<Local> {
    // zeroed() rather than a struct literal: timespec carries extra padding
    // fields on some targets, and naming only two would not compile there.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    let mono_ns = ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64;
    Local::now() - chrono::Duration::nanoseconds(mono_ns)
}

// ---------------------------------------------------------
// 7. Startup integrity check
// ---------------------------------------------------------
/// NOW-8: the previous code returned the genesis hash whenever the WAL was
/// absent, so deleting the file outright produced a pristine, perfectly
/// verifying chain over an empty history. Deletion gave a better result than
/// tampering did.
///
/// Chain position now lives in a separate state file, so the WAL and the state
/// have to agree. A disagreement is recorded as a sealed CRITICAL event in the
/// new chain rather than being silently accepted.
///
/// Honest limit: root can delete both files. That case is caught off-box and
/// nowhere else. A fresh start mints a new K0, so verification against the
/// escrowed K0 fails, which is the anchor that makes the deletion visible to
/// whoever holds it.
struct Resume {
    key: [u8; 32],
    epoch: u64,
    seq: u64,
    last_mac: String,
    alert: Option<String>,
}

fn wal_tail() -> Option<AgentLog> {
    // ponytail: reads the whole WAL to get its last line. Fine against the 256MB
    // cap; switch to a bounded tail-seek if that ceiling is ever raised.
    let contents = fs::read_to_string(WAL_PATH).ok()?;
    contents
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<AgentLog>(l).ok())
}

fn resume_position(state: PersistedState) -> Result<Resume, anyhow::Error> {
    let decoded = hex::decode(&state.key)
        .map_err(|e| anyhow::anyhow!("seal state key is not valid hex: {}", e))?;
    if decoded.len() != 32 {
        anyhow::bail!("seal state key is {} bytes, expected 32", decoded.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);

    // The state file is a floor, not an exact position. It is checkpointed once
    // per epoch, so after an unclean shutdown the WAL legitimately runs ahead of
    // it by up to one epoch of records. Treating a mismatch in that direction as
    // tampering would cry wolf on every crash restart -- and, worse, resuming
    // from the stale seq would reissue sequence numbers and break the chain.
    //
    // What the state genuinely proves is that the WAL must never be BEHIND it.
    let from_state = Resume {
        key,
        epoch: state.epoch,
        seq: state.seq,
        last_mac: state.last_mac.clone(),
        alert: None,
    };

    let Some(tail) = wal_tail() else {
        if state.seq > 0 {
            return Ok(Resume {
                alert: Some(format!(
                    "WAL missing or empty at startup, but seal state records seq={} mac={}. \
                     Records were deleted while the agent was down.",
                    state.seq, state.last_mac
                )),
                ..from_state
            });
        }
        return Ok(from_state);
    };

    if tail.seq < state.seq {
        return Ok(Resume {
            alert: Some(format!(
                "WAL tail is behind the seal state. Expected at least seq={}, found seq={}. \
                 {} records were removed from the tail while the agent was down.",
                state.seq,
                tail.seq,
                state.seq - tail.seq
            )),
            ..from_state
        });
    }

    if tail.epoch > state.epoch {
        return Ok(Resume {
            alert: Some(format!(
                "WAL tail claims epoch={} but the sealing key is only at epoch={}. \
                 Key evolution is one-way, so these records could not have been \
                 written by this agent.",
                tail.epoch, state.epoch
            )),
            ..from_state
        });
    }

    // Records written after the last checkpoint are in the current epoch, so we
    // still hold the key that sealed them and can check them. An attacker who
    // appended to the WAL while the agent was down cannot produce a valid tag
    // without that key, and gets caught here.
    if tail.epoch == state.epoch {
        if !verify_record(&key, &tail) {
            return Ok(Resume {
                alert: Some(format!(
                    "WAL tail at seq={} does not verify against the current sealing key. \
                     It was altered or appended by something without the key.",
                    tail.seq
                )),
                ..from_state
            });
        }
    }
    // tail.epoch < state.epoch means the agent evolved and checkpointed without
    // writing a record afterwards. That key is destroyed, so the tail cannot be
    // checked here -- verify.py does it later, from the escrowed K0.

    eprintln!(
        "Resuming sealed chain at seq={} epoch={} (state checkpoint was seq={})",
        tail.seq, state.epoch, state.seq
    );
    Ok(Resume {
        seq: tail.seq,
        last_mac: tail.hash,
        ..from_state
    })
}

// ---------------------------------------------------------
// 8. Pinned map
// ---------------------------------------------------------
/// Clears a pinned map left behind by a previous run.
///
/// This does NOT recover missed events, and cannot as written: a PerfEventArray's
/// data lives in per-CPU ring buffers that are only readable while userspace is
/// attached, so pinning it keeps the map alive but retains nothing to replay.
/// Real crash recovery needs a kernel-side buffer that survives detach (e.g. a
/// RingBuf or a pinned Queue drained on startup).
fn handle_crash_recovery(path: &Path) -> Result<(), anyhow::Error> {
    if path.exists() {
        eprintln!("WARNING: Found pinned map from a previous run at {:?}", path);
        eprintln!("WARNING: Events missed while the agent was down are NOT recoverable; removing stale pin.");
        fs::remove_file(path)?;
    }
    Ok(())
}

/// SEN-6: the severe case for a loose pin is not disclosure, it is write.
/// Anyone able to open the pinned array for writing can inject fabricated
/// events straight into the agent's read path, which the agent then seals as
/// genuine. That yields arbitrary forged records inside a tamper-evident log,
/// signed by the defender, which is worse than having no log at all.
fn restrict_pin(path: &Path) {
    match fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        Ok(()) => {}
        Err(e) => eprintln!(
            "WARNING: could not restrict permissions on {:?}: {}. \
             Anyone with CAP_BPF may be able to inject forged events.",
            path, e
        ),
    }
}

// ---------------------------------------------------------
// 9. Main
// ---------------------------------------------------------
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    let shipping_enabled = opt.collector_url.is_some();

    let self_pid = std::process::id();
    let boot = monotonic_epoch();

    prepare_wal_dir()?;

    // Chain state before the WAL is opened, so the integrity check sees the
    // file exactly as the previous run left it.
    let resume = match load_state() {
        Some(state) => resume_position(state)?,
        None => {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key)
                .map_err(|e| anyhow::anyhow!("could not generate seal key: {}", e))?;
            eprintln!("================================================================");
            eprintln!("FIRST START: root sealing key (K0) for this agent.");
            eprintln!();
            eprintln!("    {}", hex::encode(key));
            eprintln!();
            eprintln!("Record this OFF THIS MACHINE now. It is printed once and never");
            eprintln!("again: the key on disk evolves forward every {}s and the old", EPOCH_SECS);
            eprintln!("generations are destroyed, which is what makes records written");
            eprintln!("before a compromise unforgeable. Without K0 held elsewhere,");
            eprintln!("nothing here can be verified.");
            eprintln!("================================================================");

            // A WAL that already exists on a first start means the state file
            // was removed on its own. The new K0 will not verify the old
            // records, so say so now rather than letting it surface as a
            // mystery failure in verify.py.
            if Path::new(WAL_PATH).exists() {
                eprintln!(
                    "WARNING: a WAL already exists but there is no seal state. Records \
                     written before this point were sealed under a key that is now gone \
                     and can no longer be verified."
                );
            }

            Resume {
                key,
                epoch: 0,
                seq: 0,
                last_mac: GENESIS_MAC.to_string(),
                alert: None,
            }
        }
    };

    let Resume { key, epoch, seq, last_mac, alert: startup_alert } = resume;

    let (wal_std, wal_len) = open_wal_locked(WAL_PATH)?;
    let mut wal = BufWriter::new(tokio::fs::File::from_std(wal_std));

    let (tx, mut rx) = mpsc::channel::<ProcessEvent>(CHANNEL_CAPACITY);

    let dropped = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));

    // ---------------------------------------------------------
    // Consumer: owns the chain, so sealing stays serialized no matter how
    // many CPU sensors feed it.
    // ---------------------------------------------------------
    let consumer = tokio::spawn(async move {
        let mut sealer = Sealer::new(key, epoch, seq, last_mac);
        let mut wal_bytes = wal_len;

        // The startup integrity alert is itself a sealed record, so the gap is
        // permanently part of the chain rather than a line on a console nobody
        // was watching.
        if let Some(msg) = startup_alert {
            eprintln!("CRITICAL: {}", msg);
            let mut alert = AgentLog {
                timestamp: Local::now().to_rfc3339(),
                severity: "CRITICAL".to_string(),
                event_type: "WAL_INTEGRITY_ALERT".to_string(),
                pid: self_pid,
                process_name: "edr-agent".to_string(),
                filename: msg,
                ..Default::default()
            };
            sealer.seal(&mut alert);
            if let Some(j) = serialize_record(&alert) {
                let line = format!("{}\n", j);
                if wal.write_all(line.as_bytes()).await.is_ok() {
                    wal_bytes += line.len() as u64;
                }
                let _ = wal.flush().await;
                println!("{}", j);
            }
            persist_state(&sealer.snapshot()).await;
        }

        let mut flush_tick =
            tokio::time::interval(Duration::from_millis(FLUSH_INTERVAL_MS));

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    let Some(ev) = maybe else { break };

                    let (process_name, name_bad) = decode_name(&ev.cmd);
                    let (parent_process_name, parent_bad) = decode_name(&ev.pcomm);
                    let (filename, path_bad) = decode_name(&ev.filename);

                    let severity = severity_for(
                        &process_name,
                        &parent_process_name,
                        name_bad || parent_bad || path_bad,
                    );

                    // Only pay for the /proc lookup on events that already matter.
                    let binary_id = if severity == "INFO" {
                        String::new()
                    } else {
                        binary_identity(ev.pid)
                    };

                    let event_time = boot
                        + chrono::Duration::nanoseconds(ev.ktime_ns as i64);

                    let mut log = AgentLog {
                        timestamp: event_time.to_rfc3339(),
                        ktime_ns: ev.ktime_ns,
                        severity: severity.to_string(),
                        event_type: "PROCESS_EXEC".to_string(),
                        uid: ev.uid,
                        pid: ev.pid,
                        ppid: ev.ppid,
                        cgroup_id: ev.cgroup_id,
                        process_name,
                        parent_process_name,
                        filename,
                        binary_id,
                        ..Default::default()
                    };

                    sealer.seal(&mut log);

                    let Some(json) = serialize_record(&log) else { continue };
                    let line = format!("{}\n", json);

                    // NOW-14: rotate before writing rather than after, so the
                    // cap is a ceiling and not a target the WAL overshoots.
                    if wal_bytes + line.len() as u64 > MAX_WAL_BYTES {
                        if let Err(e) = wal.flush().await {
                            eprintln!("CRITICAL: WAL flush before rotation failed: {}", e);
                        }
                        match rotate_wal().await {
                            Ok(f) => {
                                wal = BufWriter::new(f);
                                wal_bytes = 0;
                                eprintln!(
                                    "WAL rotated to {}. Ship or archive it before the next \
                                     rotation overwrites it.",
                                    WAL_ARCHIVE_PATH
                                );
                            }
                            Err(e) => {
                                eprintln!("CRITICAL: WAL rotation failed, continuing to append: {}", e);
                            }
                        }
                    }

                    if let Err(e) = wal.write_all(line.as_bytes()).await {
                        eprintln!("CRITICAL: WAL write failed at seq={}: {}", log.seq, e);
                    } else {
                        wal_bytes += line.len() as u64;
                    }

                    println!("{}", json);
                }

                _ = flush_tick.tick() => {
                    // Batched rather than per record. The old code fsynced every
                    // event, which is the single largest cost in the userspace
                    // path and works against the requirement that the agent run
                    // continuously without being felt.
                    if let Err(e) = wal.flush().await {
                        eprintln!("CRITICAL: WAL flush failed: {}", e);
                    }
                    if tokio::time::Instant::now() >= sealer.next_evolve {
                        sealer.evolve();
                        sealer.next_evolve =
                            tokio::time::Instant::now() + Duration::from_secs(EPOCH_SECS);
                        persist_state(&sealer.snapshot()).await;
                    }
                }
            }
        }

        if let Err(e) = wal.flush().await {
            eprintln!("CRITICAL: final WAL flush failed: {}", e);
        }
        if let Err(e) = wal.get_mut().sync_all().await {
            eprintln!("CRITICAL: final WAL sync failed: {}", e);
        }
        persist_state(&sealer.snapshot()).await;
    });

    // ---------------------------------------------------------
    // Load BPF
    // ---------------------------------------------------------
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/edr-agent-ebpf"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        debug!("Standard eBPF logger not active: {}", e);
    }

    let program: &mut TracePoint = bpf
        .program_mut("edr_agent")
        .ok_or_else(|| anyhow::anyhow!("program 'edr_agent' not found in the BPF object"))?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    eprintln!("EDR Agent Active. Streaming JSON logs...");

    let pin_path = Path::new(PIN_PATH);
    handle_crash_recovery(pin_path)?;

    let mut event_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?;

    eprintln!("Pinning map to: {:?}", pin_path);
    event_map.pin(pin_path)?;
    restrict_pin(pin_path);

    let mut events = AsyncPerfEventArray::try_from(event_map)?;

    // ---------------------------------------------------------
    // Sensors
    // ---------------------------------------------------------
    let cpus = online_cpus().map_err(|(msg, error)| anyhow::anyhow!("{}: {}", msg, error))?;

    let mut sensors = Vec::new();

    for cpu_id in cpus {
        // NOW-2: aya's default is 2 pages, i.e. 8 KB per CPU, which holds about
        // 40 of these events. An exec burst -- a build starting, a package
        // install -- overruns that in a few milliseconds and the kernel drops
        // the overflow silently. Dropping events is the outcome an attacker
        // wants, and it is cheap to induce on purpose by making noise.
        //
        // 16 pages is 64 KB per CPU, ~340 events of headroom, and costs about
        // 1 MB of RSS on a 16-core host. Raise it if `lost in the perf ring`
        // ever shows up in the health line.
        let mut buf = events.open(cpu_id, Some(16))?;
        let tx = tx.clone();
        let dropped = Arc::clone(&dropped);
        let lost = Arc::clone(&lost);
        let rejected = Arc::clone(&rejected);

        sensors.push(tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // Never unwrap here: a panic would silently take this CPU's
                // coverage offline while the agent still looks healthy.
                let batch = match buf.read_events(&mut buffers).await {
                    Ok(batch) => batch,
                    Err(e) => {
                        eprintln!(
                            "CRITICAL: perf read failed on CPU {}, sensor stopping: {}",
                            cpu_id, e
                        );
                        break;
                    }
                };

                // NOW-2: the ring reports what it had to throw away, and the
                // old code read only `.read` and discarded it. An attacker
                // floods the host with trivial execs until the ring overflows,
                // then acts inside the gap. Silent loss is the one failure an
                // EDR must never have.
                if batch.lost > 0 {
                    lost.fetch_add(batch.lost as u64, Ordering::Relaxed);
                    eprintln!(
                        "CRITICAL: perf ring dropped {} events on CPU {}. This is a \
                         detection gap, not a statistic.",
                        batch.lost, cpu_id
                    );
                }

                // Once per batch, not once per event: this is a vDSO call, but
                // the common path here is measured in single-digit microseconds
                // and there is no reason to spend any of it per record.
                let now_ns = monotonic_now_ns();

                for i in 0..batch.read {
                    let raw = &buffers[i];

                    // NOW-3: a short or truncated perf record made the old
                    // unchecked cast read past the end of the buffer.
                    if raw.len() < std::mem::size_of::<ProcessEvent>() {
                        eprintln!(
                            "WARNING: undersized perf record on CPU {} ({} bytes, expected {}); \
                             discarding.",
                            cpu_id,
                            raw.len(),
                            std::mem::size_of::<ProcessEvent>()
                        );
                        continue;
                    }

                    let ptr = raw.as_ptr() as *const ProcessEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    // AGT-8: never report our own execs. Not reachable today
                    // since the agent spawns nothing, but if a helper is ever
                    // added this is what stops the agent feeding itself in a
                    // loop bounded only by the channel.
                    if data.pid == self_pid {
                        continue;
                    }

                    // SEN-6: refuse to seal something the kernel could not have
                    // produced. A rejection here means someone is writing to
                    // the pinned map, which is not a condition with a benign
                    // explanation.
                    if let Some(why) = implausible(&data, now_ns) {
                        rejected.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "CRITICAL: rejected an implausible event on CPU {} ({}). \
                             Something is writing to the pinned map at {}.",
                            cpu_id, why, PIN_PATH
                        );
                        continue;
                    }

                    // AGT-4: try_send rather than send. Blocking here applies
                    // backpressure all the way up into the perf ring, turning a
                    // slow consumer into silent kernel-side loss. Dropping at a
                    // point where it can be counted is the lesser evil.
                    if tx.try_send(data).is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // ---------------------------------------------------------
    // Health watchdog
    // ---------------------------------------------------------
    // SEN-3: `bpftool prog detach` stops collection and the process carries on
    // looking perfectly healthy. Checking that the pin is still there does not
    // prevent a detach, but it removes the attacker's best outcome, which is a
    // green dashboard over a host that stopped reporting.
    let health = tokio::spawn({
        let dropped = Arc::clone(&dropped);
        let lost = Arc::clone(&lost);
        let rejected = Arc::clone(&rejected);
        let ship_cursor = shipping_enabled.then(|| CURSOR_PATH.to_string());
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(HEALTH_INTERVAL_SECS));
            tick.tick().await;
            loop {
                tick.tick().await;

                if !Path::new(PIN_PATH).exists() {
                    eprintln!(
                        "CRITICAL: pinned map {} has disappeared. The BPF program may have \
                         been detached and this agent may no longer be collecting.",
                        PIN_PATH
                    );
                }

                let d = dropped.load(Ordering::Relaxed);
                let l = lost.load(Ordering::Relaxed);
                let r = rejected.load(Ordering::Relaxed);
                if d > 0 || l > 0 {
                    eprintln!(
                        "CRITICAL: telemetry gaps since start: {} dropped at the channel, \
                         {} lost in the perf ring.",
                        d, l
                    );
                }
                if r > 0 {
                    eprintln!(
                        "CRITICAL: {} implausible events rejected since start. Genuine \
                         tracepoint hits never fail these checks.",
                        r
                    );
                }

                // Shipping lag is a security signal, not an operational one: a
                // growing gap means records exist only on a host that may
                // already be compromised.
                if let Some(path) = &ship_cursor {
                    eprintln!("shipping high-water mark: seq {}", shipper::acked_seq(path));
                }
            }
        }
    });

    // ---------------------------------------------------------
    // Shipper
    // ---------------------------------------------------------
    // STO-4 / NOW-3: without this the seq numbers are decoration. They only
    // become proof of anything once something off-box remembers how high they
    // got, because a chain with its tail removed verifies perfectly on the host
    // that removed it.
    let ship = match &opt.collector_url {
        Some(url) => {
            let cfg = shipper::ShipperConfig {
                url: url.clone(),
                host_id: opt
                    .host_id
                    .clone()
                    .unwrap_or_else(shipper::default_host_id),
                build_id: shipper::self_build_id(),
                wal_path: WAL_PATH.to_string(),
                archive_path: WAL_ARCHIVE_PATH.to_string(),
                cursor_path: CURSOR_PATH.to_string(),
                batch_max: opt.ship_batch.max(1),
                poll: Duration::from_secs(opt.ship_interval.max(1)),
            };
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            Some((tokio::spawn(shipper::run(cfg, stop_rx)), stop_tx))
        }
        None => {
            eprintln!(
                "WARNING: no --collector-url. Records are sealed and written locally but \
                 nothing leaves this host, so deletion of the newest records cannot be \
                 detected by anything except an operator running verify.py by hand."
            );
            None
        }
    };

    // Main holds no sender of its own; only the sensors do. Dropping it here
    // means the channel closes as soon as the last sensor is gone.
    drop(tx);

    // NOW-9: SIGINT alone was not enough. systemd sends SIGTERM on
    // `systemctl stop`, which bypassed the drain entirely and discarded every
    // buffered event on each legitimate restart, and on any `kill` an attacker
    // cared to send.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
        _ = sigint.recv() => info!("SIGINT received, shutting down"),
    }

    // ---------------------------------------------------------
    // Graceful shutdown
    // ---------------------------------------------------------
    // Stop the sensors first so their senders drop, then drain the consumer.
    // Returning from main directly would discard everything still buffered,
    // which is exactly what the WAL exists to prevent.
    health.abort();
    for sensor in sensors {
        sensor.abort();
    }
    if let Err(e) = consumer.await {
        eprintln!("CRITICAL: logger task did not shut down cleanly: {}", e);
    }

    // Shipper last, and only after the consumer has flushed: it reads the WAL,
    // so draining it before the final flush would leave the newest records
    // behind on a host that is about to stop reporting.
    if let Some((handle, stop)) = ship {
        let _ = stop.send(());
        match tokio::time::timeout(Duration::from_secs(30), handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("WARNING: shipper did not stop cleanly: {}", e),
            Err(_) => eprintln!(
                "WARNING: shipper did not finish its final drain within 30s; \
                 unshipped records stay in the WAL for the next start."
            ),
        }
    }

    eprintln!("WAL flushed and seal state persisted. Agent stopped.");

    // NOTE: We do NOT unpin here. We want the kernel map to survive exit.
    Ok(())
}

/// Rename the current WAL aside and open a fresh one.
///
/// Only one archive generation is kept, so the chain spans at most two files.
/// Both must be shipped or archived for the chain to remain verifiable end to
/// end; verify.py takes them in order.
async fn rotate_wal() -> Result<tokio::fs::File, anyhow::Error> {
    let archive = PathBuf::from(WAL_ARCHIVE_PATH);
    if archive.exists() {
        fs::remove_file(&archive)?;
    }
    fs::rename(WAL_PATH, &archive)?;
    let (f, _) = open_wal_locked(WAL_PATH)?;
    Ok(tokio::fs::File::from_std(f))
}
