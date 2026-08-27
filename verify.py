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

    print("selftest passed: sealing, chaining, sequencing and key evolution all"
          " behave as specified.")


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
