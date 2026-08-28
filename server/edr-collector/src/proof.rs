//! Retrieval: the proof bundle, the read API that serves it, and the offline
//! checker that validates one.
//!
//! This is the artifact the whole commitment layer exists to produce. A bundle
//! must be checkable by someone with **no access to this collector** and **no
//! K0**: it carries the record's own bytes, the audit path from its leaf to its
//! batch chainhash, the path from that batch's level-2 leaf to the fleet-wide
//! root, and whatever the chain has to say about that root. `verify.py --proof`
//! is the independent implementation of exactly that check.
//!
//! Three rules run through everything below:
//!
//!   * **Never serve a proof that does not reproduce.** If the bytes in
//!     `events/{host}.ndjson` no longer hash to the leaf the batch committed
//!     to, that IS the tampering this feature detects. It returns 500 and logs
//!     CRITICAL. Dressing it up as a plausible-looking proof would be the worst
//!     available outcome.
//!   * **Say what a proof does not prove.** Every bundle carries `not_claims`
//!     verbatim. A proof that gets over-read in an incident report is a
//!     liability.
//!   * **Reads never take a host lock.** The events file is append-only, so a
//!     concurrent ingest can only add bytes past the range being read. The
//!     index lock is taken briefly to clone index entries and released before
//!     any file I/O (see LOCK ORDER on `App`).

use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use edr_record::{merkle, AgentLog};

use crate::{
    audit, batches_path, events_path, hex_string, leaf_for_line, level2_leaves, roots_path, unhex,
    valid_host_id, App, BatchIndexEntry, BatchLine, MerkleIndex, RootIndexEntry, RootLine,
};

/// Bulk retrieval default and ceiling. Same shape as the alert endpoints:
/// every list endpoint caps, because these enumerate records.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// Anything a bundle request can fail with. Carries the status because the
/// distinction matters: 404 is "no such record", 500 is "this collector's store
/// disagrees with its own commitment", and those must never be confused.
pub(crate) struct ProofError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl ProofError {
    fn not_found(message: impl Into<String>) -> Self {
        ProofError {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    fn diverged(message: impl Into<String>) -> Self {
        ProofError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------
// anchors.ndjson -- written by edr-anchor, read here
// ---------------------------------------------------------

/// One line of `anchors.ndjson`.
///
/// Deliberately permissive: a different process (`edr-anchor`, which must not
/// even be able to read `hosts/`) writes this file, and a newer version of it
/// may add fields or phases. Everything past the identity of the transaction is
/// optional so a forward-compatible line is surfaced rather than dropped.
/// `anchor_line_shape_is_pinned` holds the exact schema against drift.
#[derive(Deserialize, Clone)]
pub(crate) struct AnchorLine {
    pub(crate) phase: String,
    pub(crate) root_id: u64,
    #[serde(default)]
    pub(crate) root: String,
    #[serde(default)]
    pub(crate) chain_id: u64,
    #[serde(default)]
    pub(crate) tx: String,
    #[serde(default)]
    pub(crate) from: Option<String>,
    #[serde(default)]
    pub(crate) nonce: Option<u64>,
    #[serde(default)]
    pub(crate) submitted_at: Option<String>,
    #[serde(default)]
    pub(crate) block_number: Option<u64>,
    #[serde(default)]
    pub(crate) block_hash: Option<String>,
    #[serde(default)]
    pub(crate) block_time: Option<String>,
    #[serde(default)]
    pub(crate) confirmations: Option<u64>,
    #[serde(default)]
    pub(crate) confirmed_at: Option<String>,
}

pub(crate) fn anchors_path(dir: &Path) -> std::path::PathBuf {
    dir.join("anchors.ndjson")
}

/// Every anchor line, grouped by root, in file order.
///
/// ponytail: re-read per request rather than indexed in memory. It has to be:
/// a separate process appends to this file, so anything cached here goes stale
/// the moment a root is confirmed. One tx per root interval is ~144 lines a day;
/// memoise on file length if that ever shows up in a latency graph.
pub(crate) fn load_anchors(dir: &Path) -> HashMap<u64, Vec<AnchorLine>> {
    let mut by_root: HashMap<u64, Vec<AnchorLine>> = HashMap::new();
    let Ok(raw) = std::fs::read_to_string(anchors_path(dir)) else {
        return by_root;
    };
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AnchorLine>(line) {
            Ok(a) => by_root.entry(a.root_id).or_default().push(a),
            Err(e) => eprintln!("WARNING: unparseable anchor line: {}", e),
        }
    }
    by_root
}

/// The live anchor for one root: newest confirmed, else newest submitted, with
/// anything a `reorged` line disowned removed from consideration.
///
/// A reorg is recorded as a new line, never as an edit -- so resolving the
/// current state means reading the whole history of that root, not the last
/// line of it.
pub(crate) fn resolve_anchor(lines: &[AnchorLine]) -> Option<&AnchorLine> {
    let dead: HashSet<&str> = lines
        .iter()
        .filter(|l| l.phase == "reorged")
        .map(|l| l.tx.as_str())
        .collect();
    let live = |phase: &str| {
        lines
            .iter()
            .rev()
            .find(|l| l.phase == phase && !dead.contains(l.tx.as_str()))
    };
    live("confirmed").or_else(|| live("submitted"))
}

/// Chain ids a verifier is likely to meet. Anything else is reported by number,
/// which is all a verifier actually needs -- the name is a convenience.
fn chain_name(chain_id: u64) -> String {
    match chain_id {
        1 => "ethereum".to_string(),
        10 => "optimism".to_string(),
        137 => "polygon".to_string(),
        8453 => "base".to_string(),
        42161 => "arbitrum-one".to_string(),
        11155111 => "sepolia".to_string(),
        84532 => "base-sepolia".to_string(),
        421614 => "arbitrum-sepolia".to_string(),
        31337 => "anvil-local".to_string(),
        other => format!("chain-{}", other),
    }
}

/// The `anchor` block of a bundle, or the honest "not yet" version of it.
///
/// A pending root is still worth serving: it is a commitment this collector
/// cannot retroactively change without breaking `prev_root`. It is simply not
/// yet independently timestamped, and the bundle says so rather than implying
/// otherwise.
fn anchor_json(anchors: &HashMap<u64, Vec<AnchorLine>>, root_id: u64) -> Value {
    let lines = anchors.get(&root_id);
    let Some(a) = lines.and_then(|l| resolve_anchor(l)) else {
        return json!({
            "status": "pending",
            "anchored_by": null,
            "detail": "this root is sealed but not yet published on a chain. The commitment \
                       is real and chains to the previous root; it is not yet independently \
                       timestamped.",
        });
    };
    // `from` and `nonce` are written on the submitted line; the confirmation
    // that supersedes it names only the block. Carry them forward from the
    // submission of the SAME transaction so a verifier can check `to == from`
    // against the account it expects.
    let submitted = lines.and_then(|l| l.iter().find(|s| s.phase == "submitted" && s.tx == a.tx));
    let from = a.from.clone().or_else(|| submitted.and_then(|s| s.from.clone()));
    let nonce = a.nonce.or_else(|| submitted.and_then(|s| s.nonce));

    json!({
        "status": if a.phase == "confirmed" { "confirmed" } else { "submitted" },
        "chain_id": a.chain_id,
        "chain_name": chain_name(a.chain_id),
        "tx": a.tx,
        "from": from,
        "nonce": nonce,
        "submitted_at": a.submitted_at,
        "block_number": a.block_number,
        "block_hash": a.block_hash,
        "block_time": a.block_time,
        "confirmations": a.confirmations,
        "confirmed_at": a.confirmed_at,
        "calldata_rule": CALLDATA_RULE,
        "verify_with": "eth_getTransactionByHash on any RPC for this chain; compare bytes \
                        6..38 of `input` against root, and check that `to` equals `from`",
    })
}

/// The on-chain payload format, stated in every bundle so a verifier needs
/// nothing but the bundle. Kept in step with edr-anchor's `calldata()`.
pub(crate) const CALLDATA_RULE: &str = "0x4544524d5231 (\"EDRMR1\") || root(32 bytes) || \
                                        root_id(u64 big-endian)";

// ---------------------------------------------------------
// Reading one line back out of an append-only file
// ---------------------------------------------------------

/// Read the line starting at `offset`. Used with the `line_offset` the index
/// keeps, so a proof reads one line instead of a whole file.
///
/// Bounded by `MAX_LINE`: the offset comes from the index rather than from a
/// request, but a corrupt index entry pointing into the middle of a large file
/// must not read the rest of it into memory.
fn read_line_at(path: &Path, offset: u64) -> Option<String> {
    const MAX_LINE: usize = 8 * 1024 * 1024;
    let mut f = std::fs::File::open(path).ok()?;
    if offset >= f.metadata().ok()?.len() {
        return None;
    }
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = f.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        let read = chunk.get(..n)?;
        match read.iter().position(|b| *b == b'\n') {
            Some(end) => {
                buf.extend_from_slice(read.get(..end)?);
                break;
            }
            None => buf.extend_from_slice(read),
        }
        if buf.len() > MAX_LINE {
            return None;
        }
    }
    String::from_utf8(buf).ok()
}

fn read_batch_line(dir: &Path, host: &str, offset: u64) -> Option<BatchLine> {
    let line = read_line_at(&batches_path(dir, host), offset)?;
    serde_json::from_str(&line).ok()
}

fn read_root_line(dir: &Path, offset: u64) -> Option<RootLine> {
    let line = read_line_at(&roots_path(dir), offset)?;
    serde_json::from_str(&line).ok()
}

/// The committed bytes of one batch, as whole lines.
///
/// The byte range is a hint, per the storage schema: if it no longer parses the
/// caller falls back rather than trusting it. Nothing here indexes or slices
/// past a bound taken from the file's own length.
fn read_committed_lines(dir: &Path, host: &str, b: &BatchLine) -> Option<Vec<String>> {
    let path = events_path(dir, host);
    let mut f = std::fs::File::open(&path).ok()?;
    let len = f.metadata().ok()?.len();
    if b.byte_end < b.byte_start || b.byte_end > len {
        return None;
    }
    let span = b.byte_end.saturating_sub(b.byte_start);
    f.seek(SeekFrom::Start(b.byte_start)).ok()?;
    let mut buf = vec![0u8; span.min(u32::MAX as u64) as usize];
    f.read_exact(&mut buf).ok()?;
    let text = String::from_utf8(buf).ok()?;
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn decode_leaves(b: &BatchLine) -> Option<Vec<[u8; 32]>> {
    b.leaves.iter().map(|h| unhex(h)).collect()
}

// ---------------------------------------------------------
// The bundle
// ---------------------------------------------------------

/// Everything a proof needs that is not on disk: this host's batch index and
/// the root index, cloned under the index lock and used with no lock held.
pub(crate) struct IndexSnapshot {
    pub(crate) batches: Vec<BatchIndexEntry>,
    pub(crate) roots: Vec<RootIndexEntry>,
}

impl IndexSnapshot {
    fn from_index(index: &MerkleIndex, host: &str) -> Self {
        IndexSnapshot {
            batches: index.batches.get(host).cloned().unwrap_or_default(),
            roots: index.roots.clone(),
        }
    }

    /// For the CLI, which has no running server and so builds the index by
    /// scanning the data dir exactly as `serve` does at startup.
    pub(crate) fn from_disk(dir: &Path, host: &str) -> Self {
        IndexSnapshot::from_index(&MerkleIndex::load(dir), host)
    }
}

/// Which batches could hold `seq` for this host.
///
/// ponytail: linear over one host's batch index. It is NOT a binary search on
/// purpose -- `enroll --force` resets a chain to seq 1, so the seq ranges are
/// not globally ascending and a binary search would silently miss the older
/// segment. Index by segment if a single host ever accumulates enough batches
/// for the scan to matter.
fn candidate_batches<'a>(
    batches: &'a [BatchIndexEntry],
    seq: u64,
    segment: Option<u64>,
) -> Vec<&'a BatchIndexEntry> {
    batches
        .iter()
        .filter(|b| b.seq_lo != 0 && seq >= b.seq_lo && seq <= b.seq_hi)
        .filter(|b| match segment {
            Some(s) => b.segment == s,
            None => true,
        })
        .collect()
}

/// Build every proof bundle for `(host, seq[, segment])`.
///
/// More than one is a real answer, not an error: `seq` is unique only within a
/// segment, and a forced re-enrollment can repeat even that. Guessing which one
/// the caller meant would be worse than handing back both.
///
/// Pure file I/O and hashing -- call it from `spawn_blocking`.
pub(crate) fn bundles_for(
    dir: &Path,
    snap: &IndexSnapshot,
    host: &str,
    seq: u64,
    segment: Option<u64>,
) -> Result<Vec<Value>, ProofError> {
    let anchors = load_anchors(dir);
    let candidates = candidate_batches(&snap.batches, seq, segment);
    if candidates.is_empty() {
        return Err(ProofError::not_found(format!(
            "no sealed batch for {} covers seq {}. Either it was never ingested, it was \
             ingested with --merkle off, or the batch covering it has not been sealed.",
            host, seq
        )));
    }

    let mut out = Vec::new();
    for entry in candidates {
        match bundle_for_batch(dir, snap, &anchors, host, seq, entry) {
            Ok(Some(bundle)) => out.push(bundle),
            Ok(None) => {}
            Err(e) => return Err(e),
        }
    }
    if out.is_empty() {
        return Err(ProofError::not_found(format!(
            "seq {} is inside a sealed byte range for {} but no line in it carries that seq",
            seq, host
        )));
    }
    Ok(out)
}

/// One bundle, or None if this batch turned out not to contain the record.
fn bundle_for_batch(
    dir: &Path,
    snap: &IndexSnapshot,
    anchors: &HashMap<u64, Vec<AnchorLine>>,
    host: &str,
    seq: u64,
    entry: &BatchIndexEntry,
) -> Result<Option<Value>, ProofError> {
    let Some(batch) = read_batch_line(dir, host, entry.line_offset) else {
        return Err(ProofError::diverged(format!(
            "batch {} for {} no longer reads from batches/{}.ndjson at the offset the index \
             holds. The batch file was rewritten or truncated.",
            entry.batch_id, host, host
        )));
    };
    let Some(lines) = read_committed_lines(dir, host, &batch) else {
        eprintln!(
            "CRITICAL: the committed byte range {}..{} of host {} batch {} no longer reads \
             from the events file. Lines were removed or the file was truncated.",
            batch.byte_start, batch.byte_end, host, batch.batch_id
        );
        return Err(ProofError::diverged(format!(
            "the bytes batch {} for {} commits to are no longer readable",
            batch.batch_id, host
        )));
    };

    // The leaf index counts EVERY committed line, markers included -- a marker
    // is a leaf like any other, and skipping them would shift every index after
    // the first CHAIN_BREAK.
    let mut found: Option<(usize, AgentLog, Value, &str)> = None;
    for (i, line) in lines.iter().enumerate() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(rec_value) = v.get("record") else {
            continue;
        };
        if rec_value.get("seq").and_then(Value::as_u64) != Some(seq) {
            continue;
        }
        let Ok(rec) = serde_json::from_value::<AgentLog>(rec_value.clone()) else {
            continue;
        };
        found = Some((i, rec, v, line.as_str()));
        break;
    }
    let Some((index, record, stored, raw_line)) = found else {
        return Ok(None);
    };

    // The check the whole feature turns on. If the stored bytes no longer hash
    // to what was committed, that is precisely the tampering this detects --
    // refuse, loudly. Serving a plausible-looking proof over altered bytes
    // would be the worst possible outcome.
    // Recomputed exactly as ingest computed it, over the ORIGINAL stored bytes
    // -- not over a re-serialisation of the parsed value, which would silently
    // normalise away whatever was changed.
    let recomputed = leaf_for_line(raw_line);
    let Some(leaves) = decode_leaves(&batch) else {
        return Err(ProofError::diverged(format!(
            "batch {} for {} carries a leaf that is not 64 hex characters",
            batch.batch_id, host
        )));
    };
    match leaves.get(index) {
        Some(stored_leaf) if *stored_leaf == recomputed => {}
        Some(stored_leaf) => {
            eprintln!(
                "CRITICAL: collector store diverges from its own commitment at {}/seq {}: \
                 leaf {} recomputes to {} but batch {} committed {}. Those bytes were \
                 altered after they were sealed.",
                host,
                seq,
                index,
                hex_string(&recomputed),
                batch.batch_id,
                hex_string(stored_leaf)
            );
            return Err(ProofError::diverged(format!(
                "the stored record at {}/seq {} does not match the commitment made for it. \
                 No proof will be issued for it. Run `edr-collector merkle-audit --host {}`.",
                host, seq, host
            )));
        }
        None => {
            return Err(ProofError::diverged(format!(
                "batch {} for {} commits to {} leaf/leaves but the byte range now holds {}",
                batch.batch_id,
                host,
                leaves.len(),
                lines.len()
            )))
        }
    }

    let Some(batch_path) = merkle::path(&leaves, index) else {
        return Err(ProofError::diverged(format!(
            "no audit path for leaf {} of batch {} for {}",
            index, batch.batch_id, host
        )));
    };
    // Belt and braces: never hand out a path that does not replay here first.
    let Some(chainhash) = unhex(&batch.chainhash) else {
        return Err(ProofError::diverged(format!(
            "batch {} for {} has an unusable chainhash",
            batch.batch_id, host
        )));
    };
    if !merkle::verify_path(recomputed, index, leaves.len(), &batch_path, chainhash) {
        eprintln!(
            "CRITICAL: the audit path for {}/seq {} does not replay to the chainhash batch {} \
             recorded. The batch line and its leaves disagree.",
            host, seq, batch.batch_id
        );
        return Err(ProofError::diverged(format!(
            "batch {} for {} does not reproduce its own chainhash",
            batch.batch_id, host
        )));
    }

    let root_block = root_block_for(dir, snap, host, batch.batch_id, &chainhash)?;

    Ok(Some(json!({
        "v": 1,
        "record": record,
        "collector_metadata": {
            "host": host,
            "received_at": stored.get("received_at"),
            "segment": stored.get("segment"),
            "verified": stored.get("verified"),
        },
        "leaf": {
            "tag": "0x00",
            "hash": hex_string(&recomputed),
            "preimage_rule": "SHA256(0x00 || sealed_payload(record) || raw(record.hash))",
        },
        "batch": {
            "host": host,
            "batch_id": batch.batch_id,
            "count": leaves.len(),
            "index": index,
            "chainhash": batch.chainhash,
            "prev_chainhash": batch.prev_chainhash,
            "sealed_at": batch.sealed_at,
            "path": path_json(&batch_path),
        },
        "root": root_block,
        "anchor": match root_block_id(&root_block) {
            Some(root_id) => anchor_json(anchors, root_id),
            None => json!({
                "status": "unsealed",
                "anchored_by": null,
                "detail": "this batch is committed but no fleet-wide root covers it yet. \
                           It will be sealed into the next root.",
            }),
        },
        "claims": claims(&root_block, anchors),
        "not_claims": NOT_CLAIMS,
    })))
}

fn root_block_id(root_block: &Value) -> Option<u64> {
    root_block.get("root_id").and_then(Value::as_u64)
}

/// The level-2 half of a bundle: this batch's leaf, and its path to the sealed
/// fleet-wide root.
fn root_block_for(
    dir: &Path,
    snap: &IndexSnapshot,
    host: &str,
    batch_id: u64,
    chainhash: &[u8; 32],
) -> Result<Value, ProofError> {
    let batch_leaf = merkle::batch_leaf(host, batch_id, chainhash);

    let Some(entry) = snap.roots.iter().find(|r| {
        r.covers
            .iter()
            .any(|(h, lo, hi)| h == host && batch_id >= *lo && batch_id <= *hi)
    }) else {
        return Ok(json!({
            "root_id": null,
            "batch_leaf": hex_string(&batch_leaf),
            "batch_leaf_rule": BATCH_LEAF_RULE,
            "detail": "no sealed root covers this batch yet",
        }));
    };

    let Some(root) = read_root_line(dir, entry.line_offset) else {
        return Err(ProofError::diverged(format!(
            "root {} no longer reads from roots.ndjson at the offset the index holds",
            entry.root_id
        )));
    };
    let Some(leaves) = level2_leaves(&root.covers) else {
        return Err(ProofError::diverged(format!(
            "root {} carries a chainhash that is not 64 hex characters",
            root.root_id
        )));
    };
    let Some(index) = leaves.iter().position(|l| *l == batch_leaf) else {
        eprintln!(
            "CRITICAL: root {} claims to cover {} batch {}, but that batch's level-2 leaf is \
             not in the leaf vector the root line rebuilds to.",
            root.root_id, host, batch_id
        );
        return Err(ProofError::diverged(format!(
            "root {} does not actually cover {} batch {}",
            root.root_id, host, batch_id
        )));
    };
    let Some(root_path) = merkle::path(&leaves, index) else {
        return Err(ProofError::diverged(format!(
            "no audit path for level-2 leaf {} of root {}",
            index, root.root_id
        )));
    };
    let Some(root_hash) = unhex(&root.root) else {
        return Err(ProofError::diverged(format!(
            "root {} has an unusable root hash",
            root.root_id
        )));
    };
    if !merkle::verify_path(batch_leaf, index, leaves.len(), &root_path, root_hash) {
        eprintln!(
            "CRITICAL: root {} does not reproduce from the chainhashes it carries. The root \
             line was altered.",
            root.root_id
        );
        return Err(ProofError::diverged(format!(
            "root {} does not reproduce its own root hash",
            root.root_id
        )));
    }

    Ok(json!({
        "root_id": root.root_id,
        "root": root.root,
        "prev_root": root.prev_root,
        "leaf_count": leaves.len(),
        "index": index,
        "sealed_at": root.sealed_at,
        "batch_leaf": hex_string(&batch_leaf),
        "batch_leaf_rule": BATCH_LEAF_RULE,
        "path": path_json(&root_path),
    }))
}

const BATCH_LEAF_RULE: &str = "SHA256(0x03 || lp(host) || lp(batch_id_decimal) || raw(chainhash)), \
                               lp(x) = u32 big-endian length || x";

/// Emitted verbatim in every bundle. Overclaiming here is worse than not
/// building the feature at all.
const NOT_CLAIMS: [&str; 3] = [
    "This does NOT prove the record is authentic; that requires the HMAC under the escrowed K0.",
    "This does NOT prove when the traced event occurred, only when the commitment was published.",
    "This does NOT prove no record was omitted before batching.",
];

fn claims(root_block: &Value, anchors: &HashMap<u64, Vec<AnchorLine>>) -> Vec<String> {
    let Some(root_id) = root_block_id(root_block) else {
        return vec![
            "This record's bytes were committed to a batch chainhash by this collector."
                .to_string(),
            "No fleet-wide root covers that batch yet, so nothing outside this collector pins \
             it."
                .to_string(),
        ];
    };
    let root = root_block
        .get("root")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)");
    let anchor = anchors.get(&root_id).and_then(|l| resolve_anchor(l));
    match anchor {
        Some(a) if a.phase == "confirmed" => vec![
            format!(
                "This record's bytes were committed to root {} before block {}.",
                root,
                a.block_number.unwrap_or_default()
            ),
            format!(
                "Block {} was mined at {} (per the chain), on chain id {}.",
                a.block_number.unwrap_or_default(),
                a.block_time.clone().unwrap_or_else(|| "(unknown)".into()),
                a.chain_id
            ),
        ],
        Some(a) => vec![
            format!("This record's bytes were committed to root {}.", root),
            format!(
                "Transaction {} publishing that root has been broadcast but is not yet \
                 confirmed to the configured depth.",
                a.tx
            ),
        ],
        None => vec![
            format!("This record's bytes were committed to root {}.", root),
            "That root is not yet published on a chain, so it is not yet independently \
             timestamped."
                .to_string(),
        ],
    }
}

fn path_json(path: &[([u8; 32], bool)]) -> Vec<Value> {
    path.iter()
        .map(|(h, left)| json!({"h": hex_string(h), "left": left}))
        .collect()
}

// ---------------------------------------------------------
// Offline bundle verification (the CLI half of verify.py --proof)
// ---------------------------------------------------------

/// Check a bundle with no collector, no K0 and no network: recompute the leaf,
/// replay both paths, recompute the level-2 leaf.
///
/// Returns one line per step so an operator sees which link failed rather than
/// a single boolean. Mirrors `check_bundle()` in verify.py step for step; the
/// two are meant to be independently written and identically strict.
pub(crate) fn check_bundle(bundle: &Value) -> (Vec<(bool, String)>, bool) {
    fn step(pass: bool, msg: String, steps: &mut Vec<(bool, String)>) -> bool {
        steps.push((pass, msg));
        pass
    }
    let mut steps: Vec<(bool, String)> = Vec::new();
    let mut ok = true;

    // 1. the record's own bytes hash to the leaf the bundle claims.
    let leaf_claim = bundle
        .get("leaf")
        .and_then(|l| l.get("hash"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let record_leaf = bundle
        .get("record")
        .and_then(|r| serde_json::from_value::<AgentLog>(r.clone()).ok())
        .and_then(|r| merkle::record_leaf(&r));
    let leaf = match record_leaf {
        Some(l) if hex_string(&l) == leaf_claim => {
            ok &= step(
                true,
                format!("leaf recomputes from the record: {}", leaf_claim),
                &mut steps,
            );
            Some(l)
        }
        Some(l) => {
            ok &= step(
                false,
                format!(
                    "leaf recomputes to {} but the bundle claims {}",
                    hex_string(&l),
                    leaf_claim
                ),
                &mut steps,
            );
            Some(l)
        }
        None => {
            ok &= step(
                false,
                "the bundle's record does not decode, so its leaf cannot be recomputed"
                    .to_string(),
                &mut steps,
            );
            None
        }
    };

    // 2. the audit path replays from that leaf to the batch chainhash.
    let batch = bundle.get("batch").cloned().unwrap_or(Value::Null);
    let chainhash = batch.get("chainhash").and_then(Value::as_str).unwrap_or("");
    let b_index = batch.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
    let b_count = batch.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
    let b_path = decode_path(batch.get("path"));
    match (leaf, unhex(chainhash), b_path.as_ref()) {
        (Some(l), Some(ch), Some(p)) if merkle::verify_path(l, b_index, b_count, p, ch) => {
            ok &= step(
                true,
                format!(
                    "leaf {} of {} replays to batch chainhash {}",
                    b_index, b_count, chainhash
                ),
                &mut steps,
            );
        }
        _ => {
            ok &= step(
                false,
                format!(
                    "the batch audit path does not replay from leaf {} to chainhash {}",
                    b_index, chainhash
                ),
                &mut steps,
            );
        }
    }

    // 3. the level-2 leaf recomputes from (host, batch_id, chainhash).
    let root = bundle.get("root").cloned().unwrap_or(Value::Null);
    let host = batch.get("host").and_then(Value::as_str).unwrap_or("");
    let batch_id = batch.get("batch_id").and_then(Value::as_u64).unwrap_or(0);
    let claimed_batch_leaf = root
        .get("batch_leaf")
        .and_then(Value::as_str)
        .unwrap_or("");
    let batch_leaf = unhex(chainhash).map(|ch| merkle::batch_leaf(host, batch_id, &ch));
    match batch_leaf {
        Some(bl) if hex_string(&bl) == claimed_batch_leaf => {
            ok &= step(
                true,
                format!("batch leaf recomputes: {}", claimed_batch_leaf),
                &mut steps,
            );
        }
        Some(bl) => {
            ok &= step(
                false,
                format!(
                    "batch leaf recomputes to {} but the bundle claims {}",
                    hex_string(&bl),
                    claimed_batch_leaf
                ),
                &mut steps,
            );
        }
        None => {
            ok &= step(
                false,
                "the batch chainhash is not 64 hex characters".to_string(),
                &mut steps,
            );
        }
    }

    // 4. the level-2 path replays to the sealed root.
    match root.get("root_id").and_then(Value::as_u64) {
        None => {
            steps.push((
                true,
                "no fleet-wide root covers this batch yet, so there is nothing further to \
                 replay. The commitment is this collector's alone."
                    .to_string(),
            ));
        }
        Some(root_id) => {
            let r_index = root.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            let r_count = root.get("leaf_count").and_then(Value::as_u64).unwrap_or(0) as usize;
            let r_root = root.get("root").and_then(Value::as_str).unwrap_or("");
            let r_path = decode_path(root.get("path"));
            match (batch_leaf, unhex(r_root), r_path.as_ref()) {
                (Some(bl), Some(rh), Some(p))
                    if merkle::verify_path(bl, r_index, r_count, p, rh) =>
                {
                    ok &= step(
                        true,
                        format!(
                            "batch leaf {} of {} replays to root {} ({})",
                            r_index, r_count, root_id, r_root
                        ),
                        &mut steps,
                    );
                }
                _ => {
                    ok &= step(
                        false,
                        format!(
                            "the root audit path does not replay from index {} to root {}",
                            r_index, r_root
                        ),
                        &mut steps,
                    );
                }
            }
        }
    }

    (steps, ok)
}

fn decode_path(v: Option<&Value>) -> Option<Vec<([u8; 32], bool)>> {
    let arr = v?.as_array()?;
    arr.iter()
        .map(|e| {
            let h = unhex(e.get("h")?.as_str()?)?;
            let left = e.get("left")?.as_bool()?;
            Some((h, left))
        })
        .collect()
}

// ---------------------------------------------------------
// HTTP surface -- dashboard socket only
// ---------------------------------------------------------

/// These endpoints enumerate records and hand out record content, so they live
/// on the analyst-facing socket with the rest of the read API. The ingest
/// socket is reachable by a proxy the threat model already treats as hostile.
pub fn routes(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/merkle/status", get(merkle_status))
        .route("/api/merkle/record", get(merkle_record))
        .route("/api/merkle/records", get(merkle_records))
        .route("/api/merkle/batch/{host}/{batch_id}", get(merkle_batch))
        .route("/api/merkle/roots", get(merkle_roots))
        .route("/api/merkle/root/{root_id}", get(merkle_root))
        .route("/api/merkle/tx/{tx}", get(merkle_tx))
        .route("/api/merkle/audit", get(merkle_audit))
        .layer(axum::middleware::from_fn(no_store))
        .with_state(app)
}

/// A proof bundle is record content. It must not sit in a shared cache, and
/// nothing here is ever a document, so the strictest CSP applies.
async fn no_store(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

fn bad_request(msg: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg})))
}

/// Index counters plus how far behind the anchor worker is.
///
/// `roots_unanchored` and `oldest_unanchored_age_secs` are the two an operator
/// alerts on: a stuck anchor worker is a monitoring event, not a data-loss
/// event, but it is invisible unless something surfaces it.
async fn merkle_status(State(app): State<Arc<App>>) -> impl IntoResponse {
    let (batches, hosts, roots, pending, root_ids) = {
        let index = app.merkle.lock().await;
        (
            index.batches.values().map(Vec::len).sum::<usize>(),
            index.batches.len(),
            index.roots.len(),
            index.pending.len(),
            index
                .roots
                .iter()
                .map(|r| (r.root_id, r.sealed_at.clone()))
                .collect::<Vec<_>>(),
        )
    };

    let dir = app.data_dir.clone();
    let merkle_enabled = app.merkle_enabled;
    let body = tokio::task::spawn_blocking(move || {
        let anchors = load_anchors(&dir);
        let status = read_anchor_status(&dir);
        let mut unanchored = 0u64;
        let mut oldest: Option<String> = None;
        for (root_id, sealed_at) in &root_ids {
            let confirmed = anchors
                .get(root_id)
                .and_then(|l| resolve_anchor(l))
                .is_some();
            if !confirmed {
                unanchored += 1;
                if oldest.is_none() {
                    oldest = Some(sealed_at.clone());
                }
            }
        }
        let age = oldest.as_deref().and_then(age_secs);
        let last = anchors
            .values()
            .filter_map(|l| resolve_anchor(l))
            .max_by_key(|a| a.root_id);

        json!({
            "merkle": if merkle_enabled { "on" } else { "off" },
            "hosts_with_batches": hosts,
            "batches": batches,
            "roots": roots,
            "batches_pending_root": pending,
            "roots_unanchored": unanchored,
            "oldest_unanchored_sealed_at": oldest,
            "oldest_unanchored_age_secs": age,
            "last_anchor": last.map(|a| json!({
                "root_id": a.root_id,
                "root": a.root,
                "status": a.phase,
                "tx": a.tx,
                "chain_id": a.chain_id,
                "chain_name": chain_name(a.chain_id),
                "block_number": a.block_number,
                "block_time": a.block_time,
            })),
            "anchor_worker": status,
        })
    })
    .await
    .unwrap_or_else(|e| json!({"error": format!("status task did not complete: {}", e)}));

    Json(body)
}

/// `anchor-status.json`, if edr-anchor is running and writing it.
///
/// A separate file rather than a line in anchors.ndjson: that file is evidence
/// and is append-only, and a liveness/balance heartbeat is neither. Absent
/// means the worker has never run here, which is itself worth showing.
fn read_anchor_status(dir: &Path) -> Value {
    match std::fs::read_to_string(dir.join("anchor-status.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    {
        Some(v) => v,
        None => json!(null),
    }
}

fn age_secs(rfc3339: &str) -> Option<i64> {
    let t = chrono::DateTime::parse_from_rfc3339(rfc3339).ok()?;
    Some(
        chrono::Utc::now()
            .signed_duration_since(t.with_timezone(&chrono::Utc))
            .num_seconds()
            .max(0),
    )
}

#[derive(Deserialize)]
struct RecordQuery {
    host: Option<String>,
    seq: Option<u64>,
    segment: Option<u64>,
}

/// The primary endpoint: the full proof bundle for one record.
async fn merkle_record(
    State(app): State<Arc<App>>,
    Query(q): Query<RecordQuery>,
) -> impl IntoResponse {
    let Some(host) = q.host.filter(|h| valid_host_id(h)) else {
        return bad_request("host is required and must be a valid host id");
    };
    let Some(seq) = q.seq else {
        return bad_request("seq is required");
    };

    let snap = {
        let index = app.merkle.lock().await;
        IndexSnapshot::from_index(&index, &host)
    };
    let dir = app.data_dir.clone();
    let segment = q.segment;

    // File reads and hashing off the runtime threads, and with no lock held --
    // the events file is append-only, so a concurrent ingest can only add bytes
    // past the range being read.
    let built = tokio::task::spawn_blocking(move || bundles_for(&dir, &snap, &host, seq, segment))
        .await;

    match built {
        Ok(Ok(bundles)) => (
            StatusCode::OK,
            Json(json!({
                "count": bundles.len(),
                "note": "seq is unique only within a segment, and a forced re-enrollment can \
                         repeat even that. Every match is returned rather than one guessed.",
                "proofs": bundles,
            })),
        ),
        Ok(Err(e)) => (e.status, Json(json!({"error": e.message}))),
        Err(join) => {
            eprintln!("CRITICAL: proof task did not complete: {}", join);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "proof task did not complete"})),
            )
        }
    }
}

#[derive(Deserialize)]
struct RecordsQuery {
    host: Option<String>,
    from_seq: Option<u64>,
    to_seq: Option<u64>,
    severity: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    include_proof: bool,
}

/// Bulk retrieval over a seq range, optionally with a proof per record.
///
/// `include_proof` is off by default and the limit is capped hard when it is
/// on: a bundle is two file reads and a tree walk, and a thousand of them in
/// one request is a self-inflicted outage.
async fn merkle_records(
    State(app): State<Arc<App>>,
    Query(q): Query<RecordsQuery>,
) -> impl IntoResponse {
    let Some(host) = q.host.filter(|h| valid_host_id(h)) else {
        return bad_request("host is required and must be a valid host id");
    };
    let (Some(from_seq), Some(to_seq)) = (q.from_seq, q.to_seq) else {
        return bad_request("from_seq and to_seq are required");
    };
    if to_seq < from_seq {
        return bad_request("to_seq must not be below from_seq");
    }
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .min(if q.include_proof { 50 } else { MAX_LIMIT })
        .max(1);

    let snap = {
        let index = app.merkle.lock().await;
        IndexSnapshot::from_index(&index, &host)
    };
    let dir = app.data_dir.clone();
    let severity = q.severity.unwrap_or_default();
    let include_proof = q.include_proof;

    let rows = tokio::task::spawn_blocking(move || {
        let mut rows: Vec<Value> = Vec::new();
        for entry in snap.batches.iter() {
            if entry.seq_lo == 0 || entry.seq_hi < from_seq || entry.seq_lo > to_seq {
                continue;
            }
            let Some(batch) = read_batch_line(&dir, &host, entry.line_offset) else {
                continue;
            };
            let Some(lines) = read_committed_lines(&dir, &host, &batch) else {
                continue;
            };
            for line in lines {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let Some(rec) = v.get("record") else { continue };
                let Some(seq) = rec.get("seq").and_then(Value::as_u64) else {
                    continue;
                };
                if seq < from_seq || seq > to_seq {
                    continue;
                }
                if !severity.is_empty()
                    && rec.get("severity").and_then(Value::as_str) != Some(severity.as_str())
                {
                    continue;
                }
                let mut row = json!({
                    "host": host,
                    "batch_id": batch.batch_id,
                    "received_at": v.get("received_at"),
                    "segment": v.get("segment"),
                    "verified": v.get("verified"),
                    "record": rec,
                });
                if include_proof {
                    let segment = v.get("segment").and_then(Value::as_u64);
                    match bundles_for(&dir, &snap, &host, seq, segment) {
                        Ok(mut b) if !b.is_empty() => {
                            row["proof"] = b.remove(0);
                        }
                        Ok(_) => row["proof"] = Value::Null,
                        Err(e) => row["proof_error"] = json!(e.message),
                    }
                }
                rows.push(row);
                if rows.len() >= limit {
                    return rows;
                }
            }
        }
        rows
    })
    .await
    .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({"count": rows.len(), "limit": limit, "records": rows})),
    )
}

/// One batch line, its leaves, and where it landed on chain.
async fn merkle_batch(
    State(app): State<Arc<App>>,
    UrlPath((host, batch_id)): UrlPath<(String, u64)>,
) -> impl IntoResponse {
    if !valid_host_id(&host) {
        return bad_request("invalid host id");
    }
    let snap = {
        let index = app.merkle.lock().await;
        IndexSnapshot::from_index(&index, &host)
    };
    let Some(entry) = snap.batches.iter().find(|b| b.batch_id == batch_id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such batch for this host"})),
        );
    };
    let dir = app.data_dir.clone();
    let roots = snap.roots.clone();

    let body = tokio::task::spawn_blocking(move || {
        let Some(batch) = read_batch_line(&dir, &host, entry.line_offset) else {
            return None;
        };
        let anchors = load_anchors(&dir);
        let covering = roots.iter().find(|r| {
            r.covers
                .iter()
                .any(|(h, lo, hi)| *h == host && batch_id >= *lo && batch_id <= *hi)
        });
        Some(json!({
            "host": host,
            "batch_id": batch.batch_id,
            "sealed_at": batch.sealed_at,
            "chainhash": batch.chainhash,
            "prev_chainhash": batch.prev_chainhash,
            "count": batch.count,
            "seq_lo": batch.seq_lo,
            "seq_hi": batch.seq_hi,
            "segment": batch.segment,
            "byte_start": batch.byte_start,
            "byte_end": batch.byte_end,
            "leaves": batch.leaves,
            "root_id": covering.map(|r| r.root_id),
            "root": covering.map(|r| r.root.clone()),
            "anchor": match covering {
                Some(r) => anchor_json(&anchors, r.root_id),
                None => json!({"status": "unsealed", "anchored_by": null}),
            },
        }))
    })
    .await
    .ok()
    .flatten();

    match body {
        Some(v) => (StatusCode::OK, Json(v)),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the batch line no longer reads from disk"})),
        ),
    }
}

#[derive(Deserialize)]
struct RootsQuery {
    limit: Option<usize>,
    before_id: Option<u64>,
}

async fn merkle_roots(State(app): State<Arc<App>>, Query(q): Query<RootsQuery>) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT).max(1);
    let roots = {
        let index = app.merkle.lock().await;
        index.roots.clone()
    };
    let dir = app.data_dir.clone();
    let before = q.before_id;

    let rows = tokio::task::spawn_blocking(move || {
        let anchors = load_anchors(&dir);
        roots
            .iter()
            .rev()
            .filter(|r| match before {
                Some(b) => r.root_id < b,
                None => true,
            })
            .take(limit)
            .map(|r| {
                json!({
                    "root_id": r.root_id,
                    "root": r.root,
                    "sealed_at": r.sealed_at,
                    "hosts": r.covers.iter().map(|(h, lo, hi)| json!({
                        "host": h, "batch_lo": lo, "batch_hi": hi
                    })).collect::<Vec<_>>(),
                    "anchor": anchor_json(&anchors, r.root_id),
                })
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({"count": rows.len(), "roots": rows})),
    )
}

async fn merkle_root(
    State(app): State<Arc<App>>,
    UrlPath(root_id): UrlPath<u64>,
) -> impl IntoResponse {
    let entry = {
        let index = app.merkle.lock().await;
        index.roots.iter().find(|r| r.root_id == root_id).cloned()
    };
    let Some(entry) = entry else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such root"})),
        );
    };
    let dir = app.data_dir.clone();

    let body = tokio::task::spawn_blocking(move || {
        let root = read_root_line(&dir, entry.line_offset)?;
        let anchors = load_anchors(&dir);
        Some(json!({
            "root_id": root.root_id,
            "root": root.root,
            "prev_root": root.prev_root,
            "sealed_at": root.sealed_at,
            "leaf_count": root.leaf_count,
            "leaf_order": "hosts ascending (byte-wise), batch_id ascending within a host. This \
                           order is part of the format: a verifier that sorts differently \
                           computes a different root.",
            "covers": root.covers,
            "anchor": anchor_json(&anchors, root.root_id),
        }))
    })
    .await
    .ok()
    .flatten();

    match body {
        Some(v) => (StatusCode::OK, Json(v)),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "the root line no longer reads from disk"})),
        ),
    }
}

/// Reverse lookup: given a transaction, what does it commit to?
///
/// The answer an investigator wants when handed a tx hash from a chain
/// explorer: which root, which hosts, which sequence ranges.
async fn merkle_tx(State(app): State<Arc<App>>, UrlPath(tx): UrlPath<String>) -> impl IntoResponse {
    // The tx hash is request-derived and becomes nothing but a comparison, but
    // bound it anyway rather than carrying an arbitrary string around.
    if tx.len() > 132 || !tx.chars().all(|c| c.is_ascii_alphanumeric()) {
        return bad_request("not a transaction hash");
    }

    // anchors.ndjson is read first, with no lock held, so the index lock is
    // taken once and only for the one root this transaction names.
    let dir = app.data_dir.clone();
    let hit = tokio::task::spawn_blocking(move || {
        load_anchors(&dir)
            .into_values()
            .flatten()
            .find(|a| a.tx.trim_start_matches("0x").eq_ignore_ascii_case(tx.trim_start_matches("0x")))
    })
    .await
    .ok()
    .flatten();

    let Some(hit) = hit else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no anchor recorded for that transaction"})),
        );
    };

    let covers = {
        let index = app.merkle.lock().await;
        index
            .roots
            .iter()
            .find(|r| r.root_id == hit.root_id)
            .map(|r| {
                r.covers
                    .iter()
                    .map(|(host, lo, hi)| {
                        let seqs: Vec<&BatchIndexEntry> = index
                            .batches
                            .get(host)
                            .map(|v| {
                                v.iter()
                                    .filter(|b| b.batch_id >= *lo && b.batch_id <= *hi)
                                    .collect()
                            })
                            .unwrap_or_default();
                        json!({
                            "host": host,
                            "batch_lo": lo,
                            "batch_hi": hi,
                            "seq_lo": seqs.iter().filter(|b| b.seq_lo != 0).map(|b| b.seq_lo).min(),
                            "seq_hi": seqs.iter().map(|b| b.seq_hi).max(),
                            "lines": seqs.iter().map(|b| b.count as u64).sum::<u64>(),
                        })
                    })
                    .collect::<Vec<_>>()
            })
    };

    (
        StatusCode::OK,
        Json(json!({
            "tx": hit.tx,
            "chain_id": hit.chain_id,
            "chain_name": chain_name(hit.chain_id),
            "phase": hit.phase,
            "root_id": hit.root_id,
            "root": hit.root,
            "block_number": hit.block_number,
            "block_time": hit.block_time,
            "covers": covers,
            "calldata_rule": CALLDATA_RULE,
        })),
    )
}

#[derive(Deserialize)]
struct AuditQuery {
    host: Option<String>,
}

/// The self-check, over HTTP. Same recomputation `merkle-audit` runs on the
/// CLI, so an analyst without shell access sees the same answer.
async fn merkle_audit(State(app): State<Arc<App>>, Query(q): Query<AuditQuery>) -> impl IntoResponse {
    if let Some(h) = q.host.as_deref() {
        if !valid_host_id(h) {
            return bad_request("invalid host id");
        }
    }
    let dir = app.data_dir.clone();
    let host = q.host.clone();

    // A full audit re-hashes every committed line. Always off the runtime, and
    // never behind a host lock.
    let report = tokio::task::spawn_blocking(move || {
        let r = audit(&dir, host.as_deref());
        json!({
            "intact": r.divergences.is_empty(),
            "divergences": r.divergences,
            "note": "this checks the collector against ITS OWN commitments, with no K0 and no \
                     chain. It does not prove the records are authentic, and it cannot see a \
                     record dropped before it was ever batched.",
        })
    })
    .await
    .unwrap_or_else(|e| json!({"error": format!("audit task did not complete: {}", e)}));

    (StatusCode::OK, Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact schema edr-anchor writes, held here so a change on either side
    /// fails a test rather than silently producing bundles with no anchor.
    /// `anchor_line_shape_is_pinned` in edr-anchor asserts the same literal.
    #[test]
    fn anchor_line_shape_is_pinned() {
        let submitted = r#"{"v":1,"phase":"submitted","root_id":88,"root":"7e91",
            "chain_id":8453,"from":"0xabc","nonce":1204,"tx":"0x5f",
            "submitted_at":"2026-08-27T09:20:11Z"}"#;
        let a: AnchorLine = serde_json::from_str(submitted).expect("submitted parses");
        assert_eq!(a.phase, "submitted");
        assert_eq!(a.root_id, 88);
        assert_eq!(a.nonce, Some(1204));
        assert_eq!(a.block_number, None);

        let confirmed = r#"{"v":1,"phase":"confirmed","root_id":88,"root":"7e91",
            "chain_id":8453,"tx":"0x5f","block_number":21883014,"block_hash":"0x77",
            "block_time":"2026-08-27T09:20:37Z","confirmations":12,
            "confirmed_at":"2026-08-27T09:24:02Z"}"#;
        let c: AnchorLine = serde_json::from_str(confirmed).expect("confirmed parses");
        assert_eq!(c.block_number, Some(21883014));
        assert_eq!(c.confirmations, Some(12));

        // A newer worker adding fields must not make the collector drop the
        // line: the anchor is evidence, and unparseable evidence is invisible.
        let future = r#"{"v":2,"phase":"confirmed","root_id":9,"tx":"0x1","chain_id":1,
            "blob_gas_used":42,"something_new":{"a":1}}"#;
        let f: AnchorLine = serde_json::from_str(future).expect("unknown fields are ignored");
        assert_eq!(f.root_id, 9);
    }

    fn line(phase: &str, tx: &str) -> AnchorLine {
        serde_json::from_str(&format!(
            r#"{{"phase":"{}","root_id":1,"tx":"{}","chain_id":8453}}"#,
            phase, tx
        ))
        .expect("fixture parses")
    }

    /// A reorg is recorded as a new line, never as an edit, so resolving the
    /// current state means reading the whole history of that root.
    #[test]
    fn a_reorged_transaction_stops_counting() {
        let lines = vec![line("submitted", "0xaa"), line("confirmed", "0xaa")];
        assert_eq!(resolve_anchor(&lines).map(|a| a.tx.as_str()), Some("0xaa"));

        let reorged = vec![
            line("submitted", "0xaa"),
            line("confirmed", "0xaa"),
            line("reorged", "0xaa"),
        ];
        assert!(resolve_anchor(&reorged).is_none(), "a reorged tx proves nothing");

        let reanchored = vec![
            line("submitted", "0xaa"),
            line("confirmed", "0xaa"),
            line("reorged", "0xaa"),
            line("submitted", "0xbb"),
            line("confirmed", "0xbb"),
        ];
        assert_eq!(
            resolve_anchor(&reanchored).map(|a| a.tx.as_str()),
            Some("0xbb")
        );

        // Submitted but not yet confirmed still resolves -- the bundle says
        // "submitted" rather than pretending nothing was published.
        let inflight = vec![line("submitted", "0xcc")];
        assert_eq!(
            resolve_anchor(&inflight).map(|a| a.phase.as_str()),
            Some("submitted")
        );
    }

    #[test]
    fn a_line_reads_back_from_its_offset() {
        let dir = std::env::temp_dir().join(format!("edr-proof-line-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let p = dir.join("lines.ndjson");
        let body = "first\nsecond line\nthird\n";
        std::fs::write(&p, body).expect("write");

        assert_eq!(read_line_at(&p, 0).as_deref(), Some("first"));
        assert_eq!(read_line_at(&p, 6).as_deref(), Some("second line"));
        assert_eq!(read_line_at(&p, 18).as_deref(), Some("third"));
        // Past the end is None, not an empty line and not a panic.
        assert_eq!(read_line_at(&p, 9999), None);
        assert_eq!(read_line_at(&p, body.len() as u64), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
