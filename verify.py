#!/usr/bin/env python3
"""Offline verifier for the agent's forward-secure sealed log.

Must mirror `sealed_payload()` and `Sealer` in agent/edr-agent/src/main.rs
byte-for-byte. If the two ever drift, every record fails.

The agent prints K0 once, at first start. Without it held off the monitored
machine, nothing here proves anything: a root attacker who deletes both the WAL
and the state file gets a fresh K0 and a chain that is internally consistent.
Checking against the escrowed K0 is what turns that into a visible failure.

Usage:
    verify.py --key <K0-hex> [wal-file ...]
    verify.py --selftest

Files are verified in the order given. After a rotation the chain spans two
files, so pass the archive first:

    verify.py --key <hex> /var/log/edr/edr.wal.1 /var/log/edr/edr.wal
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys

GENESIS = "0" * 64
DEFAULT_WAL = "/var/log/edr/edr.wal"

# Order is load-bearing. This is the exact field sequence in sealed_payload().
# Ceiling on epochs of key evolution to derive for one record. 60s epochs, so
# ~2 years of continuous uptime. Keep in step with MAX_EPOCH_WALK in
# server/edr-collector/src/main.rs.
MAX_EPOCH_WALK = 1_051_200

SEALED_FIELDS = [
    "seq", "epoch", "timestamp", "ktime_ns", "severity", "event_type",
    "uid", "pid", "ppid", "cgroup_id", "process_name", "parent_process_name",
    "filename", "binary_id", "prev_hash",
]


def _lp(value):
    """Length-prefix one field: u32 big-endian length, then the bytes.

    Replaces the old '|'-joined payload, which was ambiguous because
    process_name is attacker-chosen: ("bash|sshd", "x") and ("bash", "sshd|x")
    hashed identically, so two different records could be swapped for one
    another. selftest() pins that case.
    """
    raw = str(value).encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def sealed_payload(log):
    return b"".join(_lp(log[f]) for f in SEALED_FIELDS)


# ---------------------------------------------------------------------------
# Merkle trees (RFC 6962 style)
#
# Mirrors protocol/src/merkle.rs exactly. Two properties do the security work
# and both are easy to lose by accident:
#
#   * Domain separation. Leaves are prefixed 0x00/0x02/0x03 and internal nodes
#     0x01, so no leaf preimage can be passed off as an internal node.
#   * An odd node is PROMOTED, never duplicated. Bitcoin-style padding makes
#     [a,b,c] and [a,b,c,c] hash identically (CVE-2012-2459), which would let a
#     commitment cover a set of records that was never stored.
#
# selftest() asserts the same hex constants the Rust tests assert. Drift
# between the two implementations is the failure mode in this feature that
# costs the most to find any other way -- every proof verifies on one side and
# fails on the other with no clue why -- and these constants are the cheap
# catch for it.
# ---------------------------------------------------------------------------

TAG_RECORD = 0x00   # a record line stored in events/{host}.ndjson
TAG_NODE = 0x01     # an internal node, never a leaf
TAG_MARKER = 0x02   # a collector-authored marker (CHAIN_BREAK, BUILD_MISMATCH)
TAG_BATCH = 0x03    # a batch chainhash, as a leaf of the fleet-wide root


def _leaf(tag, data):
    return hashlib.sha256(bytes([tag]) + data).digest()


def _node(left, right):
    return hashlib.sha256(bytes([TAG_NODE]) + left + right).digest()


def _largest_pow2_below(n):
    """The largest power of two strictly less than n, for n > 1.

    This split -- rather than a balanced halving -- is what makes the tree
    shape depend only on n, so a verifier who knows the leaf count can rebuild
    the shape without being told it.
    """
    if n < 2:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaves):
    """Merkle Tree Hash over already-computed leaf hashes."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_pow2_below(len(leaves))
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_path(leaves, index):
    """Audit path for `index`, bottom-up: (sibling_hash, sibling_is_left).

    None for an out-of-range index rather than an exception -- the index comes
    out of a proof bundle someone else wrote.
    """
    n = len(leaves)
    if not 0 <= index < n:
        return None
    if n == 1:
        return []
    k = _largest_pow2_below(n)
    if index < k:
        sub = merkle_path(leaves[:k], index)
        return None if sub is None else sub + [(merkle_root(leaves[k:]), False)]
    sub = merkle_path(leaves[k:], index - k)
    return None if sub is None else sub + [(merkle_root(leaves[:k]), True)]


def _replay(leaf, index, n, path):
    if not 0 <= index < n:
        return None
    if n == 1:
        # A single-leaf tree has an empty path. A non-empty one here means the
        # path is longer than the shape allows.
        return leaf if not path else None
    if not path:
        return None
    sibling, sibling_is_left = path[-1]
    rest = path[:-1]
    k = _largest_pow2_below(n)
    if index < k:
        if sibling_is_left:
            return None
        sub = _replay(leaf, index, k, rest)
        return None if sub is None else _node(sub, sibling)
    if not sibling_is_left:
        return None
    sub = _replay(leaf, index - k, n - k, rest)
    return None if sub is None else _node(sibling, sub)


def verify_path(leaf, index, n, path, root):
    """Replay an audit path from a leaf to a claimed root.

    `n` is required, not inferred: the tree shape depends on it, and letting a
    verifier guess would let a path built over one shape be replayed against
    another.
    """
    computed = _replay(leaf, index, n, list(path))
    return computed is not None and hmac.compare_digest(computed, root)


class KeySchedule:
    """K_0 given, K_{n+1} = SHA256(K_n). One-way, so a key recovered from a
    compromised host says nothing about the epochs before it."""

    def __init__(self, k0_hex):
        key = bytes.fromhex(k0_hex)
        if len(key) != 32:
            raise ValueError(f"K0 must be 32 bytes, got {len(key)}")
        self._keys = [key]

    def key_for(self, epoch):
        if epoch < 0:
            raise ValueError("negative epoch")
        # The epoch comes out of a file an attacker may have written, and it is
        # used as a loop count that also grows a list. Unbounded, one crafted
        # record hangs the verifier or exhausts its memory -- which is a cheap
        # way to stop an investigation. Matches MAX_EPOCH_WALK in the collector.
        if epoch > MAX_EPOCH_WALK:
            raise ValueError(
                f"epoch {epoch} exceeds MAX_EPOCH_WALK ({MAX_EPOCH_WALK}, ~2 years of "
                "agent uptime). Refusing to derive it; treat this record as forged."
            )
        while len(self._keys) <= epoch:
            self._keys.append(hashlib.sha256(self._keys[-1]).digest())
        return self._keys[epoch]


def record_mac(schedule, log):
    return hmac.new(
        schedule.key_for(log["epoch"]), sealed_payload(log), hashlib.sha256
    ).hexdigest()


def verify_chain(wal_files, k0_hex, quiet=False):
    def say(msg):
        if not quiet:
            print(msg)

    schedule = KeySchedule(k0_hex)

    expected_prev = GENESIS
    expected_seq = 1
    prev_epoch = 0
    total = 0
    alerts = []
    first = True

    for wal_file in wal_files:
        say(f"Verifying {wal_file}...")
        try:
            with open(wal_file, "r", encoding="utf-8") as f:
                records = [(n, line) for n, line in enumerate(f, 1) if line.strip()]
        except OSError as e:
            say(f"[ALERT] Cannot read {wal_file}: {e}")
            return False

        for line_no, line in records:
            where = f"{wal_file}:{line_no}"

            try:
                log = json.loads(line)
            except json.JSONDecodeError as e:
                say(f"[ALERT] Malformed record at {where}: {e}")
                return False

            missing = [f for f in SEALED_FIELDS + ["hash"] if f not in log]
            if missing:
                say(f"[ALERT] Record at {where} is missing fields: {missing}")
                return False

            # Present is not the same as usable. seq and epoch are compared and
            # arithmetic'd below, so a tampered string here aborts the whole run
            # with a traceback -- one bad record would stop the investigation.
            for field in ("seq", "epoch"):
                value = log[field]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    say(f"[ALERT] Record at {where} has a non-numeric {field}: {value!r}")
                    return False

            # Truncation: a removed record leaves a hole in the counter even
            # when every surviving record still verifies on its own.
            if first:
                expected_seq = log["seq"]
                if log["prev_hash"] != GENESIS and expected_seq == 1:
                    say(f"[ALERT] First record at {where} does not start from genesis.")
                    return False
                expected_prev = log["prev_hash"]
                first = False
            elif log["seq"] != expected_seq:
                say(f"[ALERT] Sequence gap at {where}!")
                say(f"   Expected seq: {expected_seq}")
                say(f"   Actual seq:   {log['seq']}")
                say("   Records were removed from the middle or the tail.")
                return False

            if log["epoch"] < prev_epoch:
                say(f"[ALERT] Epoch went backwards at {where}: "
                    f"{prev_epoch} -> {log['epoch']}. Key evolution is one-way, "
                    f"so this record was forged or reordered.")
                return False

            if log["prev_hash"] != expected_prev:
                say(f"[ALERT] Chain broken at {where}!")
                say(f"   Expected prev: {expected_prev[:16]}...")
                say(f"   Actual prev:   {log['prev_hash'][:16]}...")
                return False

            try:
                actual = record_mac(schedule, log)
            except (ValueError, TypeError) as exc:
                # TypeError covers a tampered non-numeric epoch, which would
                # otherwise abort the whole run with a traceback.
                say(f"[ALERT] Cannot verify record at {where}: {exc}")
                return False
            if not hmac.compare_digest(actual, log["hash"]):
                say(f"[ALERT] Seal does not verify at {where}!")
                say(f"   seq={log['seq']} epoch={log['epoch']}")
                say("   The record was altered after it was written, or K0 is wrong.")
                return False

            if log.get("event_type") == "WAL_INTEGRITY_ALERT":
                alerts.append((where, log.get("filename", "")))

            expected_prev = log["hash"]
            expected_seq = log["seq"] + 1
            prev_epoch = log["epoch"]
            total += 1

    say(f"All {total} records verified. Chain is intact through seq={expected_seq - 1}.")

    if alerts:
        say("")
        say("The chain is intact, but it contains sealed integrity alerts the")
        say("agent raised about itself:")
        for where, msg in alerts:
            say(f"  {where}: {msg}")
        return False

    say("Reminder: this proves nothing was altered. It cannot prove nothing was")
    say("appended after the last record you hold, or that the agent was running")
    say("the whole time. Compare seq against the collector's high-water mark.")
    return True


# ---------------------------------------------------------------------------


def selftest():
    import tempfile

    k0 = "11" * 32
    schedule = KeySchedule(k0)

    def make(seq, epoch, prev, **over):
        log = {
            "seq": seq, "epoch": epoch,
            "timestamp": f"2026-08-16T10:00:0{seq}+05:30",
            "ktime_ns": 1000 * seq, "severity": "INFO",
            "event_type": "PROCESS_EXEC", "uid": 1000, "pid": 100 + seq,
            "ppid": 42, "cgroup_id": 9999, "process_name": "bash",
            "parent_process_name": "sshd", "filename": "/usr/bin/bash",
            "binary_id": "", "prev_hash": prev, "hash": "",
        }
        log.update(over)
        log["hash"] = record_mac(schedule, log)
        return log

    def write(logs):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for log in logs:
                f.write(json.dumps(log) + "\n")
        return path

    def check(logs, should_pass, why, key=k0):
        path = write(logs)
        try:
            got = verify_chain([path], key, quiet=True)
            assert got == should_pass, f"{why}: expected pass={should_pass}, got {got}"
        finally:
            os.remove(path)

    # A clean chain that crosses an epoch boundary.
    chain = []
    prev = GENESIS
    for seq in range(1, 6):
        epoch = 0 if seq <= 2 else 1
        chain.append(make(seq, epoch, prev))
        prev = chain[-1]["hash"]
    check(chain, True, "clean chain must verify")

    # Every sealed field must be tamper-evident.
    for field, value in [
        ("ppid", 1), ("parent_process_name", "init"), ("severity", "DEBUG"),
        ("uid", 0), ("pid", 1), ("cgroup_id", 0), ("filename", "/bin/ls"),
        ("process_name", "ls"), ("timestamp", "2026-01-01T00:00:00+05:30"),
        ("ktime_ns", 0), ("event_type", "OTHER"), ("binary_id", "1:2:3"),
    ]:
        bad = [dict(r) for r in chain]
        bad[2][field] = value
        check(bad, False, f"tampering with {field} must be caught")

    # Truncating the tail leaves every surviving record internally valid. Only
    # the sequence counter catches it, and only against an external high-water
    # mark -- which is why the reminder above is not boilerplate.
    check(chain[:-1], True, "tail truncation still verifies locally (known limit)")

    # Removing from the middle breaks both the link and the counter.
    check(chain[:2] + chain[3:], False, "middle deletion must be caught")

    # Reordering.
    check(chain[:2] + [chain[3], chain[2]] + chain[4:], False,
          "reordering must be caught")

    # NOW-5 regression: under the old '|'-joined payload these two records
    # produced an identical digest and could be substituted for one another.
    a = make(1, 0, GENESIS, process_name="bash|sshd", parent_process_name="x")
    b = make(1, 0, GENESIS, process_name="bash", parent_process_name="sshd|x")
    assert a["hash"] != b["hash"], \
        "length-prefixing must disambiguate fields containing the old delimiter"

    # NOW-4: the seal is only as good as the key. A recomputed chain under a
    # different K0 is internally consistent and must still fail.
    other = KeySchedule("22" * 32)
    forged = []
    prev = GENESIS
    for seq in range(1, 4):
        log = {
            "seq": seq, "epoch": 0, "timestamp": "2026-08-16T10:00:00+05:30",
            "ktime_ns": 1, "severity": "INFO", "event_type": "PROCESS_EXEC",
            "uid": 0, "pid": 1, "ppid": 0, "cgroup_id": 0,
            "process_name": "innocent", "parent_process_name": "systemd",
            "filename": "/bin/true", "binary_id": "", "prev_hash": prev,
            "hash": "",
        }
        log["hash"] = hmac.new(
            other.key_for(0), sealed_payload(log), hashlib.sha256
        ).hexdigest()
        forged.append(log)
        prev = log["hash"]
    check(forged, False, "a chain forged under a different K0 must fail")

    # An epoch that moves backwards implies a key that moved backwards.
    rolled = [dict(r) for r in chain]
    rolled[4]["epoch"] = 0
    rolled[4]["hash"] = record_mac(schedule, rolled[4])
    check(rolled, False, "backwards epoch must be caught")

    # A crafted epoch must be refused, not derived. Unbounded, this one record
    # hangs the verifier and stops the investigation without forging anything.
    absurd = [dict(r) for r in chain]
    absurd[3]["epoch"] = 2 ** 63
    check(absurd, False, "an absurd epoch must be refused, not derived")

    # Same field, wrong type: must be an alert, not a traceback.
    typed = [dict(r) for r in chain]
    typed[3]["epoch"] = "not-a-number"
    check(typed, False, "a non-numeric epoch must be reported, not crash")

    merkle_selftest()

    print("selftest passed: sealing, chaining, sequencing, key evolution and the"
          " Merkle tree all behave as specified.")


def merkle_selftest():
    # Known-answer vectors over leaf(0x00, b"0") .. leaf(0x00, b"7").
    #
    # These hex constants are asserted identically by known_answer_vectors() in
    # protocol/src/merkle.rs. If one side is edited and the other is not, this
    # is where it shows up -- not three weeks later in a proof nobody can check.
    leaves = [_leaf(TAG_RECORD, str(i).encode()) for i in range(8)]
    for n, want in [
        (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (1, "db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03"),
        (2, "cb00989d94a569c0a678ae042b63dcd4625db96440517f37a6eb7976ea24ed4b"),
        (3, "725d5230db68f557470dc35f1d8865813acd7ebb07ad152774141decbae71327"),
        (4, "9f4a3fc20d4162dc37d4e23d907848731a76043ffff6d69288bf1abfbcff478e"),
        (8, "3b85a9626c1ccb64c6b95ec7fa64888defe2cf12e39e77e10812ce5fcb9cb58e"),
    ]:
        got = merkle_root(leaves[:n]).hex()
        assert got == want, f"merkle root over {n} leaves: {got} != {want}"

    # CVE-2012-2459: an odd node is promoted, never duplicated. Under
    # Bitcoin-style padding these two sets hash identically, so a commitment to
    # [a,b,c] would also be a commitment to [a,b,c,c] -- a different set of
    # records than the one that was actually stored. The padded root is pinned
    # as a constant too, so both implementations agree on the same pair rather
    # than merely agreeing that they differ.
    padded = leaves[:3] + [leaves[2]]
    assert merkle_root(padded).hex() == \
        "31fa70897cc42c61d9f9f1cfd0c00aeb9a0f085a62d0ec7d10c63e7862ce13a7"
    assert merkle_root(leaves[:3]) != merkle_root(padded)

    # Tags keep leaves and internal nodes apart.
    same = b"same bytes"
    assert _leaf(TAG_RECORD, same) != _leaf(TAG_MARKER, same)
    assert _leaf(TAG_RECORD, same) != _leaf(TAG_BATCH, same)
    assert _node(leaves[0], leaves[1]) != _leaf(TAG_RECORD, leaves[0] + leaves[1])

    # Round-trip over every tree size up to 17 and every leaf in it, matching
    # every_path_verifies_for_n_up_to_17 in merkle.rs.
    for n in range(1, 18):
        subset = [_leaf(TAG_RECORD, struct.pack(">I", i)) for i in range(n)]
        root = merkle_root(subset)
        for i in range(n):
            path = merkle_path(subset, i)
            assert path is not None, f"path n={n} i={i}"
            assert verify_path(subset[i], i, n, path, root), f"n={n} i={i}"

            # Flipping one bit of any sibling must break it.
            for j in range(len(path)):
                bad = list(path)
                h, side = bad[j]
                bad[j] = (bytes([h[0] ^ 0x01]) + h[1:], side)
                assert not verify_path(subset[i], i, n, bad, root), \
                    f"tampered sibling {j} of leaf {i} went undetected (n={n})"

            # A correct path replayed at the wrong index must fail.
            for wrong in range(n):
                if wrong != i:
                    assert not verify_path(subset[i], wrong, n, path, root), \
                        f"path for leaf {i} verified at index {wrong} (n={n})"

    # A path from a shorter tree must not verify against a longer one.
    four = merkle_path(leaves[:4], 1)
    assert four is not None
    assert not verify_path(leaves[1], 1, 8, four, merkle_root(leaves[:8]))
    assert not verify_path(leaves[1], 1, 4, four, merkle_root(leaves[:8]))

    # Out of range is None, not an exception.
    assert merkle_path(leaves, 8) is None
    assert merkle_path([], 0) is None


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", default=None,
                        help=f"WAL files in chain order (default: {DEFAULT_WAL})")
    parser.add_argument("--key", help="K0 in hex, as printed at first agent start. "
                                      "Falls back to $EDR_SEAL_KEY.")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        selftest()
        return 0

    k0 = args.key or os.environ.get("EDR_SEAL_KEY")
    if not k0:
        print("error: K0 is required. Pass --key or set $EDR_SEAL_KEY.")
        print("It was printed once, at the agent's first start.")
        return 2

    files = args.files or [DEFAULT_WAL]
    return 0 if verify_chain(files, k0) else 1


if __name__ == "__main__":
    sys.exit(main())
