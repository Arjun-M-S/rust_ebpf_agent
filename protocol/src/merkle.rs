//! RFC 6962-style Merkle trees: the commitment layer over stored records.
//!
//! This lives in the shared crate rather than in the collector because a proof
//! is only worth issuing if someone who does not run the collector can check
//! it. Two implementations that disagree by one byte produce proofs that
//! nobody can verify and nobody can debug, so the tree lives next to the record
//! format it commits to, and `verify.py` mirrors both against the same
//! known-answer vectors at the bottom of this file.
//!
//! Two properties do the security work, and both are easy to lose by accident:
//!
//! * **Domain separation.** Leaves are prefixed 0x00/0x02/0x03 and internal
//!   nodes 0x01, so no leaf preimage can be passed off as an internal node and
//!   no batch leaf can be passed off as a record leaf.
//! * **An odd node is promoted, never duplicated.** Bitcoin duplicates the last
//!   leaf to pad, which makes `[a,b,c]` and `[a,b,c,c]` hash to the same root
//!   (CVE-2012-2459) -- an attacker who can append one record can then produce
//!   a second, different set of records with a commitment that already matches.
//!   `cve_2012_2459_two_leaf_sets_cannot_share_a_root` pins this.
//!
//! Nothing here panics on any input: `path` returns None for an out-of-range
//! index and every slice goes through `get`. It is reachable from the collector's
//! request path, which runs under `panic = "abort"` (see the PANIC POLICY note
//! in the collector).

use sha2::{Digest, Sha256};

use crate::{sealed_payload, AgentLog};

/// A record line stored in `events/{host}.ndjson`.
pub const TAG_RECORD: u8 = 0x00;
/// An internal node. Never a leaf.
pub const TAG_NODE: u8 = 0x01;
/// A collector-authored marker line (CHAIN_BREAK, BUILD_MISMATCH).
pub const TAG_MARKER: u8 = 0x02;
/// A batch chainhash, as a leaf of the fleet-wide periodic root.
pub const TAG_BATCH: u8 = 0x03;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    fixed
}

/// `SHA256(tag || data)` -- a level-0 leaf hash.
pub fn leaf(tag: u8, data: &[u8]) -> [u8; 32] {
    sha256(&[&[tag], data])
}

/// `SHA256(0x01 || left || right)` -- an internal node.
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[TAG_NODE], left, right])
}

/// The largest power of two strictly less than `n`, for `n > 1`.
///
/// This split -- rather than a balanced halving -- is what makes the tree shape
/// depend only on `n`, so a verifier who knows the leaf count can rebuild the
/// shape without being told it.
fn largest_pow2_below(n: usize) -> usize {
    if n < 2 {
        return 0;
    }
    // The highest set bit of n-1: for n = 2,3,4,5,8,9 this gives 1,2,2,4,4,8.
    let bits = usize::BITS - 1 - (n - 1).leading_zeros();
    1usize << bits
}

/// Merkle Tree Hash over already-computed leaf hashes.
///
/// The empty tree is `SHA256("")` and a single leaf is itself -- callers hash
/// their own data through `leaf()` first, so this never re-tags.
///
/// ponytail: recomputes subtree roots rather than caching them, so building a
/// full audit path is O(n log n) hashes instead of O(n). At 500 leaves that is
/// microseconds; cache the level arrays if a batch ever gets big enough to
/// notice.
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(&[]),
        1 => match leaves.first() {
            Some(only) => *only,
            None => sha256(&[]),
        },
        n => {
            let k = largest_pow2_below(n);
            let (Some(left), Some(right)) = (leaves.get(..k), leaves.get(k..)) else {
                return sha256(&[]);
            };
            node(&root(left), &root(right))
        }
    }
}

/// Audit path for `index`, bottom-up: each entry is a sibling hash and whether
/// that sibling sits on the *left*.
///
/// Returns None for an out-of-range index rather than panicking -- the index is
/// derived from a request.
pub fn path(leaves: &[[u8; 32]], index: usize) -> Option<Vec<([u8; 32], bool)>> {
    let n = leaves.len();
    if index >= n {
        return None;
    }
    if n == 1 {
        return Some(Vec::new());
    }
    let k = largest_pow2_below(n);
    let (left, right) = (leaves.get(..k)?, leaves.get(k..)?);
    if index < k {
        let mut p = path(left, index)?;
        p.push((root(right), false));
        Some(p)
    } else {
        let mut p = path(right, index.checked_sub(k)?)?;
        p.push((root(left), true));
        Some(p)
    }
}

/// Replay an audit path from a leaf to a claimed root.
///
/// `n` is the leaf count the path was built over. It is required, not inferred:
/// the tree shape depends on it, and letting a verifier guess would let a proof
/// built over one shape be replayed against another.
pub fn verify_path(
    leaf_hash: [u8; 32],
    index: usize,
    n: usize,
    path: &[([u8; 32], bool)],
    root_hash: [u8; 32],
) -> bool {
    match replay(leaf_hash, index, n, path) {
        Some(computed) => computed == root_hash,
        None => false,
    }
}

/// Walks the same split `path` used, consuming the path from the top down --
/// the last entry is the sibling nearest the root.
fn replay(
    leaf_hash: [u8; 32],
    index: usize,
    n: usize,
    path: &[([u8; 32], bool)],
) -> Option<[u8; 32]> {
    if index >= n {
        return None;
    }
    if n == 1 {
        // A single-leaf tree has an empty path. A non-empty one here means the
        // path is longer than the shape allows.
        return if path.is_empty() {
            Some(leaf_hash)
        } else {
            None
        };
    }
    let split = path.len().checked_sub(1)?;
    let (sibling, sibling_is_left) = *path.get(split)?;
    let rest = path.get(..split)?;

    let k = largest_pow2_below(n);
    if index < k {
        // Descend left; the sibling at this level must be the right subtree.
        if sibling_is_left {
            return None;
        }
        let sub = replay(leaf_hash, index, k, rest)?;
        Some(node(&sub, &sibling))
    } else {
        if !sibling_is_left {
            return None;
        }
        let sub = replay(leaf_hash, index.checked_sub(k)?, n.checked_sub(k)?, rest)?;
        Some(node(&sibling, &sub))
    }
}

// ---------------------------------------------------------
// Leaf preimages (server.md 2.3)
// ---------------------------------------------------------

/// The u32-big-endian length prefix `sealed_payload` uses. One framing
/// convention in this codebase, not two.
fn lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Leaf for a stored record: `leaf(0x00, sealed_payload(rec) || raw(rec.hash))`.
///
/// Deliberately excludes the collector's own metadata (`received_at`,
/// `segment`, `verified`): none of it is signed by the agent, and leaving it
/// out is what lets a third party holding only the record recompute this leaf
/// with no collector state at all. That is the entire point of the proof.
///
/// Returns None if `hash` is not 64 hex characters. Such a record cannot have
/// verified, so the caller commits it as a marker leaf instead of inventing a
/// preimage for it.
pub fn record_leaf(rec: &AgentLog) -> Option<[u8; 32]> {
    let raw = hex::decode(&rec.hash).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut preimage = sealed_payload(rec);
    preimage.extend_from_slice(&raw);
    Some(leaf(TAG_RECORD, &preimage))
}

/// Leaf for a collector-authored marker line, over the exact bytes appended.
///
/// Markers carry no MAC -- the collector is the author -- so there is nothing
/// else to bind. They are committed anyway: a CHAIN_BREAK marker is the single
/// most valuable line in the file, and an uncommitted one could be deleted
/// later without trace.
pub fn marker_leaf(marker_json: &[u8]) -> [u8; 32] {
    leaf(TAG_MARKER, marker_json)
}

/// Level-2 leaf: `leaf(0x03, lp(host) || lp(batch_id) || raw(chainhash))`.
///
/// The host id is bound in because the periodic root is fleet-wide. Without it,
/// a batch proof for one host could be replayed as a proof for another.
pub fn batch_leaf(host: &str, batch_id: u64, chainhash: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(host.len() + 64);
    lp(&mut preimage, host.as_bytes());
    lp(&mut preimage, batch_id.to_string().as_bytes());
    preimage.extend_from_slice(chainhash);
    leaf(TAG_BATCH, &preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(h: &[u8; 32]) -> String {
        h.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// leaf(0x00, b"0") .. leaf(0x00, b"7")
    fn kat_leaves() -> Vec<[u8; 32]> {
        (0..8u8)
            .map(|i| leaf(TAG_RECORD, i.to_string().as_bytes()))
            .collect()
    }

    #[test]
    fn largest_pow2_below_matches_the_spec() {
        assert_eq!(largest_pow2_below(0), 0);
        assert_eq!(largest_pow2_below(1), 0);
        for (n, want) in [(2, 1), (3, 2), (4, 2), (5, 4), (8, 4), (9, 8), (17, 16)] {
            assert_eq!(largest_pow2_below(n), want, "n = {}", n);
        }
    }

    /// Every leaf of every tree size up to 17 round-trips through its own path.
    #[test]
    fn every_path_verifies_for_n_up_to_17() {
        let mut leaves = Vec::new();
        for i in 0..17u32 {
            leaves.push(leaf(TAG_RECORD, &i.to_be_bytes()));
        }
        for n in 1..=17usize {
            let Some(subset) = leaves.get(..n) else {
                panic!("subset {} exists", n)
            };
            let r = root(subset);
            for i in 0..n {
                let p = path(subset, i).unwrap_or_else(|| panic!("path n={} i={}", n, i));
                let Some(l) = subset.get(i) else {
                    panic!("leaf {} exists", i)
                };
                assert!(verify_path(*l, i, n, &p, r), "n={} i={}", n, i);
            }
        }
    }

    #[test]
    fn an_out_of_range_index_is_none_not_a_panic() {
        let leaves = kat_leaves();
        assert!(path(&leaves, 8).is_none());
        assert!(path(&leaves, usize::MAX).is_none());
        assert!(path(&[], 0).is_none());
    }

    #[test]
    fn flipping_one_bit_of_any_sibling_breaks_the_path() {
        let leaves = kat_leaves();
        let r = root(&leaves);
        for i in 0..leaves.len() {
            let base = path(&leaves, i).unwrap_or_else(|| panic!("path {}", i));
            for j in 0..base.len() {
                let mut tampered = base.clone();
                let Some(entry) = tampered.get_mut(j) else {
                    panic!("entry {}", j)
                };
                entry.0[0] ^= 0x01;
                let Some(l) = leaves.get(i) else {
                    panic!("leaf {}", i)
                };
                assert!(
                    !verify_path(*l, i, leaves.len(), &tampered, r),
                    "tampering sibling {} of leaf {} went undetected",
                    j,
                    i
                );
            }
        }
    }

    #[test]
    fn a_correct_path_replayed_at_the_wrong_index_fails() {
        let leaves = kat_leaves();
        let r = root(&leaves);
        let p = path(&leaves, 3).unwrap_or_else(|| panic!("path 3"));
        let Some(l) = leaves.get(3) else {
            panic!("leaf 3")
        };
        for wrong in 0..leaves.len() {
            if wrong == 3 {
                continue;
            }
            assert!(!verify_path(*l, wrong, leaves.len(), &p, r), "index {}", wrong);
        }
    }

    /// The reason odd nodes are promoted rather than duplicated.
    ///
    /// Under Bitcoin-style padding these two sets hash identically, so a
    /// commitment to [a,b,c] is also a commitment to [a,b,c,c] -- a different
    /// set of records than the one that was actually stored.
    #[test]
    fn cve_2012_2459_two_leaf_sets_cannot_share_a_root() {
        let leaves = kat_leaves();
        let Some(three) = leaves.get(..3) else {
            panic!("3 leaves")
        };
        let Some(dup) = leaves.get(2) else {
            panic!("leaf 2")
        };
        let mut padded = three.to_vec();
        padded.push(*dup);
        assert_ne!(root(three), root(&padded));
    }

    /// A path from a shorter tree must not verify against a longer one.
    #[test]
    fn a_path_from_a_different_tree_size_fails() {
        let leaves = kat_leaves();
        let Some(four) = leaves.get(..4) else {
            panic!("4 leaves")
        };
        let Some(eight) = leaves.get(..8) else {
            panic!("8 leaves")
        };
        let p = path(four, 1).unwrap_or_else(|| panic!("path"));
        let Some(l) = leaves.get(1) else { panic!("leaf 1") };
        assert!(!verify_path(*l, 1, 8, &p, root(eight)));
        assert!(!verify_path(*l, 1, 4, &p, root(eight)));
    }

    /// Known-answer vectors.
    ///
    /// These constants are asserted identically by `verify.py --selftest`. They
    /// are the cheap catch for Rust/Python drift, which is the failure mode in
    /// this feature that costs the most time to find any other way: every proof
    /// verifies on one side and fails on the other with no clue why.
    ///
    /// Leaves are leaf(0x00, b"0") .. leaf(0x00, b"7").
    #[test]
    fn known_answer_vectors() {
        let leaves = kat_leaves();
        let expected = [
            (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (1, "db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03"),
            (2, "cb00989d94a569c0a678ae042b63dcd4625db96440517f37a6eb7976ea24ed4b"),
            (3, "725d5230db68f557470dc35f1d8865813acd7ebb07ad152774141decbae71327"),
            (4, "9f4a3fc20d4162dc37d4e23d907848731a76043ffff6d69288bf1abfbcff478e"),
            (8, "3b85a9626c1ccb64c6b95ec7fa64888defe2cf12e39e77e10812ce5fcb9cb58e"),
        ];
        for (n, want) in expected {
            let Some(subset) = leaves.get(..n) else {
                panic!("subset {}", n)
            };
            assert_eq!(hex_of(&root(subset)), want, "root over {} leaves", n);
        }
        // The CVE case, pinned as a constant too so verify.py checks the same
        // pair rather than merely checking they differ.
        let Some(three) = leaves.get(..3) else {
            panic!("3 leaves")
        };
        let Some(dup) = leaves.get(2) else {
            panic!("leaf 2")
        };
        let mut padded = three.to_vec();
        padded.push(*dup);
        assert_eq!(
            hex_of(&root(&padded)),
            "31fa70897cc42c61d9f9f1cfd0c00aeb9a0f085a62d0ec7d10c63e7862ce13a7"
        );
    }

    #[test]
    fn tags_keep_leaves_and_nodes_apart() {
        let d = b"same bytes";
        assert_ne!(leaf(TAG_RECORD, d), leaf(TAG_MARKER, d));
        assert_ne!(leaf(TAG_RECORD, d), leaf(TAG_BATCH, d));
        // An internal node over two leaves is not the leaf of their concatenation.
        let a = leaf(TAG_RECORD, b"a");
        let b = leaf(TAG_RECORD, b"b");
        let mut cat = a.to_vec();
        cat.extend_from_slice(&b);
        assert_ne!(node(&a, &b), leaf(TAG_RECORD, &cat));
    }

    #[test]
    fn a_record_leaf_excludes_collector_metadata() {
        let mut rec = AgentLog {
            seq: 1,
            timestamp: "2026-08-27T10:00:00+00:00".to_string(),
            severity: "INFO".to_string(),
            event_type: "PROCESS_EXEC".to_string(),
            process_name: "bash".to_string(),
            prev_hash: crate::GENESIS_MAC.to_string(),
            ..Default::default()
        };
        rec.hash = crate::record_mac(&[7u8; 32], &rec);

        let Some(computed) = record_leaf(&rec) else {
            panic!("a sealed record has a 64-hex hash")
        };
        // Rebuilt from the record alone, exactly as a third party would.
        let mut preimage = sealed_payload(&rec);
        let raw = hex::decode(&rec.hash).unwrap_or_else(|_| panic!("hex"));
        preimage.extend_from_slice(&raw);
        assert_eq!(computed, leaf(TAG_RECORD, &preimage));

        // A record whose hash is not 32 raw bytes has no record leaf.
        rec.hash = "not hex".to_string();
        assert!(record_leaf(&rec).is_none());
        rec.hash = "abcd".to_string();
        assert!(record_leaf(&rec).is_none());
    }

    #[test]
    fn a_batch_leaf_binds_the_host() {
        let chain = [4u8; 32];
        assert_ne!(
            batch_leaf("web-01", 7, &chain),
            batch_leaf("web-02", 7, &chain)
        );
        assert_ne!(
            batch_leaf("web-01", 7, &chain),
            batch_leaf("web-01", 8, &chain)
        );
        // Length prefixes, not concatenation: these must not collide.
        assert_ne!(batch_leaf("ab", 1, &chain), batch_leaf("a", 11, &chain));
    }
}
