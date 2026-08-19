//! The sealed record format: written by the agent, verified by the collector,
//! mirrored by verify.py.
//!
//! This lives in the shared crate rather than in the agent because the exact
//! bytes covered by the MAC now matter to three separate programs. Three
//! independent copies of that encoding is three chances to drift apart, and the
//! failure mode of drift is every record failing to verify for a reason nobody
//! can locate. verify.py is the one copy that cannot be shared; its `SEALED_FIELDS`
//! list must be kept in step with `sealed_payload` below by hand.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// prev_hash of the first record in a chain. 64 hex zeros.
pub const GENESIS_MAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One sealed audit record.
///
/// Field order here is the JSON order; it is NOT what the MAC covers. See
/// `sealed_payload` for that, and change the two together or not at all.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct AgentLog {
    /// Monotonic, gap-free within a chain. NOW-3: the whole basis for
    /// detecting deletion; a missing seq is a missing record.
    pub seq: u64,
    /// Which generation of the sealing key signed this. Never decreases.
    pub epoch: u64,
    pub timestamp: String,
    pub ktime_ns: u64,
    pub severity: String,
    pub event_type: String,
    pub uid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub cgroup_id: u64,
    pub process_name: String,
    pub parent_process_name: String,
    pub filename: String,
    pub binary_id: String,
    /// MAC of the previous record. This is the link.
    pub prev_hash: String,
    /// MAC of this record, over `sealed_payload`.
    pub hash: String,
}

/// The exact bytes covered by the MAC.
///
/// NOW-5: every field is length-prefixed rather than delimiter-separated. The
/// old `|`-joined payload was ambiguous because process_name is chosen by the
/// attacker: `("bash|sshd", "x")` and `("bash", "sshd|x")` produced an
/// identical digest, so two different records could be swapped for one another.
/// A u32 length in front of each field makes the boundaries unforgeable.
///
/// `hash` is excluded for the obvious reason. `prev_hash` is included, which is
/// what chains the records together.
pub fn sealed_payload(log: &AgentLog) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let mut push = |field: &[u8]| {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    };

    push(log.seq.to_string().as_bytes());
    push(log.epoch.to_string().as_bytes());
    push(log.timestamp.as_bytes());
    push(log.ktime_ns.to_string().as_bytes());
    push(log.severity.as_bytes());
    push(log.event_type.as_bytes());
    push(log.uid.to_string().as_bytes());
    push(log.pid.to_string().as_bytes());
    push(log.ppid.to_string().as_bytes());
    push(log.cgroup_id.to_string().as_bytes());
    push(log.process_name.as_bytes());
    push(log.parent_process_name.as_bytes());
    push(log.filename.as_bytes());
    push(log.binary_id.as_bytes());
    push(log.prev_hash.as_bytes());
    out
}

/// One turn of the ratchet: K_{n+1} = SHA256(K_n).
pub fn evolve_key(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let out = hasher.finalize();
    let mut next = [0u8; 32];
    next.copy_from_slice(&out);
    next
}

/// K_n = SHA256^n(K0).
///
/// The direction is the entire point: a verifier holding K0 can reach any
/// epoch, and an attacker holding the on-disk K_n can reach every LATER epoch
/// but no earlier one. Records sealed before the compromise stay unforgeable.
///
/// Cost is one SHA256 per epoch, so a host up for a year at 60s epochs is
/// ~525k hashes -- well under a second, but do it once and cache it rather than
/// per record. See `KeyCache` in the collector.
pub fn derive_epoch_key(k0: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut key = *k0;
    for _ in 0..epoch {
        key = evolve_key(&key);
    }
    key
}

/// Compute the MAC for a record under a given epoch key.
pub fn record_mac(key: &[u8; 32], log: &AgentLog) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&sealed_payload(log));
    hex::encode(mac.finalize().into_bytes())
}

/// Check a record's MAC in constant time.
///
/// `verify_slice` rather than comparing hex strings: a byte-at-a-time compare
/// on a value an attacker can submit repeatedly is a forgery oracle, and
/// avoiding it costs nothing here.
pub fn verify_record(key: &[u8; 32], log: &AgentLog) -> bool {
    let Ok(expected) = hex::decode(&log.hash) else {
        return false;
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&sealed_payload(log));
    mac.verify_slice(&expected).is_ok()
}

/// Parse a 64-char hex key.
pub fn parse_key(hex_str: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(hex_str.trim()).map_err(|e| format!("not valid hex: {}", e))?;
    if decoded.len() != 32 {
        return Err(format!("key is {} bytes, expected 32", decoded.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgentLog {
        AgentLog {
            seq: 1,
            epoch: 0,
            timestamp: "2026-08-16T10:00:00+00:00".to_string(),
            ktime_ns: 12345,
            severity: "INFO".to_string(),
            event_type: "PROCESS_EXEC".to_string(),
            uid: 1000,
            pid: 42,
            ppid: 1,
            cgroup_id: 99,
            process_name: "bash".to_string(),
            parent_process_name: "sshd".to_string(),
            filename: "/bin/bash".to_string(),
            binary_id: "1:2:3".to_string(),
            prev_hash: GENESIS_MAC.to_string(),
            hash: String::new(),
        }
    }

    #[test]
    fn mac_round_trips() {
        let k = [7u8; 32];
        let mut log = sample();
        log.hash = record_mac(&k, &log);
        assert!(verify_record(&k, &log));
    }

    #[test]
    fn tampering_any_field_breaks_it() {
        let k = [7u8; 32];
        let mut log = sample();
        log.hash = record_mac(&k, &log);

        let mut t = log.clone();
        t.process_name = "sh".to_string();
        assert!(!verify_record(&k, &t));

        let mut t = log.clone();
        t.uid = 0;
        assert!(!verify_record(&k, &t));

        let mut t = log.clone();
        t.prev_hash = "ff".repeat(32);
        assert!(!verify_record(&k, &t));
    }

    /// NOW-5 regression. These two records differ only in where the boundary
    /// between two attacker-controlled fields falls. Under the old `|`-joined
    /// encoding they produced the same digest and could be swapped freely.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let k = [7u8; 32];
        let mut a = sample();
        a.process_name = "bash|sshd".to_string();
        a.parent_process_name = "x".to_string();

        let mut b = sample();
        b.process_name = "bash".to_string();
        b.parent_process_name = "sshd|x".to_string();

        assert_ne!(record_mac(&k, &a), record_mac(&k, &b));
    }

    /// The ratchet only turns one way, and a later key must not verify an
    /// earlier record.
    #[test]
    fn key_evolution_is_forward_only() {
        let k0 = [1u8; 32];
        let k1 = derive_epoch_key(&k0, 1);
        let k2 = derive_epoch_key(&k0, 2);
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_eq!(k2, evolve_key(&k1));

        let mut log = sample();
        log.hash = record_mac(&k1, &log);
        assert!(verify_record(&k1, &log));
        assert!(!verify_record(&k2, &log));
    }

    #[test]
    fn wrong_root_key_fails() {
        let mut log = sample();
        log.hash = record_mac(&[1u8; 32], &log);
        assert!(!verify_record(&[2u8; 32], &log));
    }
}
