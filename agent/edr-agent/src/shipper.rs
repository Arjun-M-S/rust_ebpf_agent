//! Ships sealed WAL records to the collector.
//!
//! Deliberately reads from the WAL rather than tapping the event channel. The
//! WAL is already the durable buffer; a second in-memory queue would duplicate
//! it, add a way to lose records the WAL already holds, and grow without bound
//! whenever the network is down. Reading from the file means an outage costs
//! nothing but a stale cursor.
//!
//! The cursor is a byte offset plus the inode it belongs to. The inode is what
//! makes rotation detectable: a WAL that suddenly has a different inode is a
//! new file, and whatever we had not read yet is now in the archive.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::Duration;

#[derive(Clone)]
pub struct ShipperConfig {
    pub url: String,
    pub host_id: String,
    /// SUP-2: dev:inode:mtime of our own executable, reported on every batch.
    /// A binary swapped for a heartbeating stub reports a different one, and
    /// the collector holds what was enrolled. The agent cannot check this for
    /// itself -- a stub would simply lie -- which is why it is sent rather than
    /// compared here.
    pub build_id: String,
    pub wal_path: String,
    pub archive_path: String,
    pub cursor_path: String,
    /// Records per batch. Also the catch-up rate limit: one batch per poll, so
    /// the drain ceiling is `batch_max / poll`. See `run` for why that matters.
    pub batch_max: usize,
    pub poll: Duration,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct Cursor {
    /// Inode the offset refers to. 0 means "not yet attached to a file".
    ino: u64,
    offset: u64,
    acked_seq: u64,
}

#[derive(Deserialize)]
struct IngestResponse {
    acked_seq: u64,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Default)]
struct Pending {
    lines: Vec<String>,
    consumed: u64,
    ino: u64,
    /// The file we were reading is finished; move to the live WAL at offset 0.
    reset: bool,
    /// The file shrank beneath our offset. Someone rewrote it.
    truncated: bool,
    /// The archive we still needed was already gone.
    lost_archive: bool,
}

fn load_cursor(path: &str) -> Cursor {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_cursor(path: &str, cursor: &Cursor) {
    let Ok(json) = serde_json::to_string(cursor) else {
        return;
    };
    // Write-then-rename: a truncated cursor file would re-ship or skip records.
    let tmp = format!("{}.tmp", path);
    let write = || -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    };
    if let Err(e) = write() {
        eprintln!("WARNING: could not persist shipper cursor: {}", e);
    }
}

/// Blocking. Called via spawn_blocking.
fn read_pending(cfg: &ShipperConfig, cursor: &Cursor) -> std::io::Result<Pending> {
    let live_ino = fs::metadata(&cfg.wal_path).map(|m| m.ino()).unwrap_or(0);

    // If our cursor names an inode that is no longer the live WAL, a rotation
    // happened while we were behind. Finish the archive before touching the
    // new file, or the records in between are never shipped.
    let reading_archive = cursor.ino != 0 && cursor.ino != live_ino;
    let path = if reading_archive {
        &cfg.archive_path
    } else {
        &cfg.wal_path
    };

    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound && reading_archive => {
            return Ok(Pending {
                ino: live_ino,
                reset: true,
                lost_archive: true,
                ..Default::default()
            });
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(Pending::default());
        }
        Err(e) => return Err(e),
    };

    let md = f.metadata()?;

    if reading_archive && md.ino() != cursor.ino {
        // Rotated twice before we drained the first archive. Only one archive
        // generation is kept, so the middle one is gone for good.
        return Ok(Pending {
            ino: live_ino,
            reset: true,
            lost_archive: true,
            ..Default::default()
        });
    }

    if md.len() < cursor.offset {
        return Ok(Pending {
            ino: md.ino(),
            truncated: true,
            ..Default::default()
        });
    }

    if md.len() == cursor.offset {
        // Nothing new. If we were draining the archive and reached its end,
        // move to the live file.
        return Ok(Pending {
            ino: if reading_archive { live_ino } else { md.ino() },
            reset: reading_archive,
            ..Default::default()
        });
    }

    f.seek(SeekFrom::Start(cursor.offset))?;

    // Bounded read: this is the catch-up rate limit made concrete. A six-hour
    // outage leaves a large WAL, and an unbounded read here would spike memory
    // and saturate the uplink at exactly the moment someone is already
    // watching the host.
    let cap = cfg.batch_max.saturating_mul(1024).min(8 * 1024 * 1024);
    let mut buf = vec![0u8; cap];
    let n = f.read(&mut buf)?;
    buf.truncate(n);

    let mut pending = Pending {
        ino: md.ino(),
        ..Default::default()
    };

    for chunk in buf.split_inclusive(|&b| b == b'\n') {
        // A chunk without a trailing newline is a partial record: the consumer
        // is mid-flush. Stop rather than ship half a line.
        if chunk.last() != Some(&b'\n') {
            break;
        }
        pending.consumed += chunk.len() as u64;
        if let Ok(s) = std::str::from_utf8(chunk) {
            let trimmed = s.trim_end();
            if !trimmed.is_empty() {
                pending.lines.push(trimmed.to_string());
            }
        }
        if pending.lines.len() >= cfg.batch_max {
            break;
        }
    }

    Ok(pending)
}

async fn ship_once(
    client: &reqwest::Client,
    cfg: &ShipperConfig,
    cursor: &mut Cursor,
) -> Result<usize, anyhow::Error> {
    let cfg_clone = cfg.clone();
    let cursor_clone = cursor.clone();
    let pending =
        tokio::task::spawn_blocking(move || read_pending(&cfg_clone, &cursor_clone)).await??;

    if pending.lost_archive {
        eprintln!(
            "CRITICAL: the WAL archive was rotated away before it could be shipped. \
             Records between seq={} and the current WAL are lost to the collector. \
             The collector will see the resulting seq gap.",
            cursor.acked_seq
        );
    }

    if pending.truncated {
        eprintln!(
            "CRITICAL: the WAL shrank below the shipper cursor ({} bytes). It was \
             truncated or replaced while the agent was running.",
            cursor.offset
        );
        cursor.offset = 0;
        cursor.ino = pending.ino;
        save_cursor(&cfg.cursor_path, cursor);
        return Ok(0);
    }

    if pending.reset {
        // Archive fully drained. Delete it now that the collector has it; this
        // is the disk that acked delivery buys back.
        if cursor.ino != 0 && !pending.lost_archive {
            let _ = fs::remove_file(&cfg.archive_path);
        }
        cursor.ino = pending.ino;
        cursor.offset = 0;
        save_cursor(&cfg.cursor_path, cursor);
        return Ok(0);
    }

    if pending.lines.is_empty() {
        if cursor.ino == 0 && pending.ino != 0 {
            cursor.ino = pending.ino;
            save_cursor(&cfg.cursor_path, cursor);
        }
        return Ok(0);
    }

    let count = pending.lines.len();
    let body = pending.lines.join("\n");

    let resp = client
        .post(format!("{}/v1/ingest", cfg.url.trim_end_matches('/')))
        .header("X-EDR-Host", &cfg.host_id)
        .header("X-EDR-Build", &cfg.build_id)
        .header("content-type", "application/x-ndjson")
        .body(body)
        .send()
        .await?;

    let status = resp.status();

    // 409 means the collector verified the batch and found the chain broken. It
    // has recorded that permanently, which is the outcome that matters -- the
    // evidence is now off-box. Advancing past it keeps later records flowing;
    // refusing to advance would wedge the shipper and blind the collector to
    // everything after the break, which is what an attacker would want.
    if status.as_u16() != 409 && !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("collector returned {}: {}", status, text.trim());
    }

    let ack: IngestResponse = resp.json().await?;

    if status.as_u16() == 409 {
        eprintln!(
            "CRITICAL: collector REJECTED the chain: {}. This is recorded off-box.",
            ack.error.as_deref().unwrap_or("chain verification failed")
        );
    }

    cursor.ino = pending.ino;
    cursor.offset += pending.consumed;
    cursor.acked_seq = ack.acked_seq;
    save_cursor(&cfg.cursor_path, cursor);

    Ok(count)
}

pub async fn run(cfg: ShipperConfig, mut shutdown: tokio::sync::oneshot::Receiver<()>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        // One connection, kept alive. Handshakes dominate the cost otherwise.
        .pool_max_idle_per_host(1)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CRITICAL: could not build HTTP client, shipping disabled: {}", e);
            return;
        }
    };

    let mut cursor = load_cursor(&cfg.cursor_path);
    eprintln!(
        "Shipper started: {} -> {} (resuming at offset {}, acked seq {})",
        cfg.host_id, cfg.url, cursor.offset, cursor.acked_seq
    );

    let mut tick = tokio::time::interval(cfg.poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // ponytail: fixed backoff, not exponential. The poll interval is already
    // seconds; an outage costs a retry every `poll` and the WAL absorbs it.
    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = &mut shutdown => {
                // Final drain. Anything still local at this point sits on a
                // host we are about to stop watching, so it is worth a few
                // extra seconds to get it off the box. Bounded so a stop
                // cannot hang on an unreachable collector.
                for _ in 0..10 {
                    match ship_once(&client, &cfg, &mut cursor).await {
                        Ok(0) => break,
                        Ok(n) => log::debug!("shutdown drain shipped {} records", n),
                        Err(e) => {
                            eprintln!(
                                "WARNING: final shipping pass failed: {}. Unshipped records \
                                 remain in the WAL and will be sent on next start.",
                                e
                            );
                            break;
                        }
                    }
                }
                eprintln!("Shipper stopped at acked seq {}", cursor.acked_seq);
                return;
            }
        }

        match ship_once(&client, &cfg, &mut cursor).await {
            Ok(0) => {
                consecutive_failures = 0;
            }
            Ok(n) => {
                consecutive_failures = 0;
                log::debug!("shipped {} records, acked seq {}", n, cursor.acked_seq);
            }
            Err(e) => {
                consecutive_failures += 1;
                // Only shout occasionally. A collector outage should not itself
                // become the thing that fills the disk with log lines.
                if consecutive_failures == 1 || consecutive_failures % 60 == 0 {
                    eprintln!(
                        "WARNING: shipping failed ({} consecutive): {}. Records are \
                         retained in the WAL.",
                        consecutive_failures, e
                    );
                }
            }
        }
    }
}

/// Best-effort host identity. The collector treats this as a claim, not proof:
/// what actually authenticates a host is that its records verify under the K0
/// escrowed for it.
pub fn default_host_id() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string())
}

/// SUP-2: identity of the running executable, as dev:inode:mtime of
/// /proc/self/exe. Replacing the binary changes it, which is the whole point.
pub fn self_build_id() -> String {
    match fs::metadata("/proc/self/exe") {
        Ok(md) => format!("{}:{}:{}", md.dev(), md.ino(), md.mtime()),
        Err(_) => "unknown".to_string(),
    }
}

/// Used by the agent to report shipping lag in its health tick.
pub fn acked_seq(cursor_path: &str) -> u64 {
    load_cursor(cursor_path).acked_seq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_trailing_line_is_not_shipped() {
        // The consumer writes with a BufWriter, so the shipper can easily read
        // a half-written record. Shipping it would break the chain at the
        // collector for a reason that is not tampering.
        let buf = b"{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3";
        let mut lines = Vec::new();
        let mut consumed = 0u64;
        for chunk in buf.split_inclusive(|&b| b == b'\n') {
            if chunk.last() != Some(&b'\n') {
                break;
            }
            consumed += chunk.len() as u64;
            lines.push(String::from_utf8_lossy(chunk).trim_end().to_string());
        }
        assert_eq!(lines.len(), 2);
        assert_eq!(consumed, 20);
    }
}
