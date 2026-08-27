# server.md — Merkle batching, blockchain anchoring, and retrieval

**Audience:** an agent/engineer who has never seen this repository.
**Deliverable:** the collector ingests telemetry from many agents concurrently, batches
stored log records into Merkle trees, publishes the periodic Merkle root to a blockchain,
and serves a retrieval API that returns any record together with a proof chaining it to
an on-chain transaction.

Concurrent multi-agent ingest is a hard requirement, not a scaling nicety: the collector
today serialises every host behind one mutex that spans an `fsync`, and the Merkle work
adds a second `fsync` to that same section. §1.6 states the problem, §2.11 is the design,
and it is **step 4 of 11** — before any commitment logic lands.

Read Part 1 completely before writing code. Every hash preimage, file path and
ordering constraint in Part 2 onward depends on facts established there.

---

# PART 1 — The system as it exists today

## 1.1 What this project is

A Linux EDR (endpoint detection & response) agent written in Rust, plus an off-box
collector. An eBPF probe traces `sched_process_exec`; every exec becomes one JSON
record. Records are HMAC-sealed into a hash chain with a forward-secure key, written
to a local write-ahead log, and shipped to the collector over HTTP. The collector
verifies each record and appends it to an append-only NDJSON store.

Repository layout — **three separate cargo workspaces**, so the server half
builds, tests and ships without the agent's toolchain:

| Component | Path | Role |
|---|---|---|
| `edr-record` | `protocol/` | the wire contract: sealed record format + crypto (`src/lib.rs`). Path-depended on by both halves; the one thing they must agree on byte-for-byte |
| `edr-collector` | `server/edr-collector/` | **off-box server — your work goes here** (`src/main.rs`, `src/dashboard.rs`) |
| `edr-agent` | `agent/edr-agent/` | userspace agent: seals, WALs, ships (`src/main.rs`, `src/shipper.rs`) |
| `edr-agent-ebpf` | `agent/edr-agent-ebpf/` | kernel probe (`no_std`), do not touch |
| `edr-agent-common` | `agent/edr-agent-common/` | kernel ↔ userspace ABI only (`ProcessEvent`), do not touch |

Total first-party code is ~3,500 lines. `agent/edr-agent-ebpf/src/vmlinux.rs` (75k lines) is
generated kernel bindings — ignore it entirely.

**You work in `server/` and `protocol/`. You never enter `agent/`.** Building the
agent needs nightly + `bpf-linker` + root; the server needs none of it:

```bash
cd server
cargo build --release
cargo test
./target/release/edr-collector --data-dir ./data serve \
    --listen 127.0.0.1:8080 --dashboard-listen 127.0.0.1:8081

cd ../protocol && cargo test          # the shared format and, once you add it, merkle.rs
```

New Merkle code that both the server and a future verifier need goes in
`protocol/`; everything collector-specific goes in `server/edr-collector/`. Adding
a dependency to `protocol/` adds it to the agent too — so keep that crate as
dependency-light as it is today (`serde`, `hmac`, `sha2`, `hex`), and note that
`sha2` being already present is why `merkle.rs` needs nothing new.

## 1.2 The threat model in one paragraph

The monitored host is assumed to fall to a root attacker. Root can edit the local log,
so the log is HMAC-sealed with a key that ratchets forward (`K_{n+1} = SHA256(K_n)`,
old key erased) — an attacker who lands at epoch *n* cannot forge records from earlier
epochs. Root can also *delete* the whole log, which is why the collector exists off-box:
it remembers the high-water sequence number, so truncation shows up as a gap. The root
key `K0` is escrowed on the collector, out of band.

**The hole you are closing:** today the *collector itself* is fully trusted. Whoever
operates it can rewrite `events/*.ndjson` after the fact and re-run `verify` with a
K0 they also hold. Nothing outside the collector pins what the store contained at a
given time. Anchoring a Merkle root on a public chain fixes exactly that: it proves
"this exact set of records existed at or before block *B*", to anyone, forever, without
trusting the collector operator and without revealing K0 or any log content.

Be precise about what anchoring does **not** do — say this in your code comments and
in the API docs, because overclaiming here is worse than not building it:

- It does **not** prove a record is authentic. Authenticity is the HMAC under K0.
- It does **not** stop the collector from *omitting* a record before it is batched.
  (Sequence-gap detection catches that; the Merkle layer does not.)
- It does **not** prove *when the event happened* — only when the commitment was
  published. The upper bound is the block timestamp; the lower bound is nothing.

## 1.3 The sealed record — exact format

Defined in `protocol/src/lib.rs`. `AgentLog` (line ~27) serialises to JSON
with these fields in this order:

```json
{"seq":1,"epoch":0,"timestamp":"2026-08-20T02:59:20.130836413+05:30",
 "ktime_ns":4968046160746,"severity":"INFO","event_type":"PROCESS_EXEC",
 "uid":1000,"pid":69453,"ppid":1651,"cgroup_id":7790,
 "process_name":"sh","parent_process_name":"Hyprland","filename":"/bin/sh",
 "binary_id":"","prev_hash":"0000…0000","hash":"d71ee7e8ae75…0380"}
```

- `seq` — monotonic, gap-free within a chain. Starts at 1.
- `epoch` — key generation, 60-second epochs, never decreases.
- `severity` — `INFO` | `MEDIUM` | `HIGH` | `CRITICAL`.
- `event_type` — the detection rule name that fired (`PROCESS_EXEC` when benign,
  otherwise e.g. `EXEC_TAMPER_TOOL`, `VOLATILE_DIR_SHELL`, `EXEC_DELETED_BINARY`).
- `prev_hash` — the previous record's `hash`; the first record uses `GENESIS_MAC`
  (64 hex zeros, `record.rs:19`).
- `hash` — HMAC-SHA256, hex, over `sealed_payload(record)` under the epoch key.

### `sealed_payload` — the bytes the MAC covers (`record.rs:57`)

Every field except `hash`, in this exact order, each **length-prefixed with a
big-endian u32** and encoded as its decimal-string / UTF-8 form:

```
seq, epoch, timestamp, ktime_ns, severity, event_type, uid, pid, ppid,
cgroup_id, process_name, parent_process_name, filename, binary_id, prev_hash
```

```rust
push(field_bytes) => out.extend(&(len as u32).to_be_bytes()); out.extend(field_bytes);
```

Length-prefixing is load-bearing: `process_name` is attacker-chosen, and the old
`|`-joined encoding let `("bash|sshd","x")` and `("bash","sshd|x")` collide.
`protocol/src/lib.rs` has a regression test pinning this
(`field_boundaries_are_unambiguous`).

**Rule: never change `sealed_payload`, the field list, or their order.** Three programs
depend on it byte-for-byte — the agent, the collector, and `verify.py` (whose
`SEALED_FIELDS` list at line ~40 is a hand-maintained mirror). Your Merkle work must
*consume* this function, never modify it. You will reuse it verbatim as the leaf preimage.

## 1.4 The collector — what it already does

`server/edr-collector/src/main.rs`. CLI (clap):

```
edr-collector [--data-dir /var/lib/edr-collector] <serve|enroll|verify|status>
  serve  --listen 127.0.0.1:8080 --dashboard-listen 127.0.0.1:8081 --silence-secs 300
  enroll --host <id> --key <K0-64-hex> [--build-id <s>] [--force]
  verify --host <id>
  status
```

Two HTTP sockets, deliberately separate:

- **ingest socket** (`--listen`, 8080): `POST /v1/ingest`, `GET /v1/status`, `GET /healthz`.
  Reachable by agents and by an untrusted TLS proxy.
- **dashboard socket** (`--dashboard-listen`, 8081): `GET /`, `/api/overview`,
  `/api/alerts`, `/api/host/{host}` — read-only, analyst-facing, must never be
  reachable from the agent side. Router built in `dashboard.rs:56`.

### On-disk layout under `--data-dir`

```
hosts/{host}.enroll.json   {"k0":"<64 hex>","build_id":…,"enrolled_at":…}   ← SECRET
hosts/{host}.state.json    HostState, rewritten atomically after every batch
events/{host}.ndjson       append-only, one JSON object per line
```

`events/{host}.ndjson` contains **two kinds of line**:

1. **Stored record** (`StoredRecord`, `main.rs:149`) — the sealed record kept
   byte-identical inside `record` so it still verifies, plus collector metadata:
   ```json
   {"received_at":"2026-08-19T21:40:50.992906391+00:00","segment":0,"verified":true,
    "record":{ …AgentLog… }}
   ```
2. **Collector marker** — written by the collector itself, has no `record` key and no
   MAC (the collector is the author):
   ```json
   {"received_at":"…","segment":1,"collector_event":"CHAIN_BREAK","at_seq":42,
    "expected_seq":41,"expected_prev_hash":"…","detail":"sequence gap: …"}
   ```
   ```json
   {"received_at":"…","segment":0,"collector_event":"BUILD_MISMATCH",
    "expected_build":"…","reported_build":"…","detail":"…"}
   ```

Markers are the investigator-facing evidence artifacts. **They must be committed to
the Merkle tree too** — see §2.3.

### The ingest handler — read this function before changing it

`async fn ingest` at `main.rs:357`. Flow:

1. Read + validate `X-EDR-Host` header (`valid_host_id`, `main.rs:233` — rejects path
   traversal since host ids become filenames). Body is `text/ndjson`, ≤ 16 MB
   (`MAX_BODY_BYTES`), typically ≤ 500 records (agent's `--ship-batch`).
2. `app.hosts.lock().await` — **one global mutex over all hosts** (`main.rs:216`). Held
   for the whole handler including the file append.
3. Lazy-load the host's enrollment + `HostState`; unenrolled hosts get 403.
4. `X-EDR-Build` compared against the enrolled build id; a mismatch emits a
   `BUILD_MISMATCH` marker.
5. `let pre_batch = entry.state.clone();` (`main.rs:456`) — snapshot for rollback.
6. For each line: parse; **skip if `rec.seq <= state.high_seq`** (idempotent replay);
   `check_record` (`main.rs:328`) checks seq continuity → epoch monotonicity →
   `prev_hash` link → MAC under the derived epoch key. On failure a `CHAIN_BREAK`
   marker is pushed into `out` *before* the record, `breaks`/`segment` increment, and
   the record is **stored anyway** with `"verified":false` — refusing to store would
   destroy the evidence. State re-anchors to the suspect record so later genuine
   records keep flowing.
7. All lines accumulate into one `String out`, appended + `sync_all()` in a single
   write (`main.rs:533`).
8. **If the append fails**, in-memory state is rolled back to `pre_batch` and the
   response acks `pre_batch.high_seq` with 500 — never ack what was not stored.
9. Lock dropped, `save_state` writes `hosts/{host}.state.json` atomically.
10. Response: `200 {"acked_seq":N}`, or `409 {"acked_seq":N,"error":"…"}` if anything
    was rejected. The agent's shipper treats 409 as "advance anyway" — the evidence is
    already off-box, and wedging would blind the collector to everything after.

### `HostState` (`main.rs:124`) — persisted per host

```rust
high_seq, high_epoch, last_mac, last_seen, breaks, segment, total_records,
silent, last_build
```

All new fields you add **must** be `#[serde(default)]` so existing state files keep
loading.

### Two consequences you must design around

- **`seq` is not globally unique.** After a chain break the collector re-anchors, and
  `enroll --force` resets chain position to zero. The unique key for a record is
  `(host, segment, seq)`, and even that can repeat across a forced re-enrollment.
  Retrieval must handle "more than one match" rather than assume one.
- **Duplicate lines are possible.** If the events append succeeds but a later step
  fails and the agent retries, the same records can be appended twice. Commit to
  **byte ranges**, not to sequence numbers, and your design is immune to this.

## 1.5 Non-negotiable house rules

Copied from the file headers; violating them will get your PR rejected.

1. **PANIC POLICY** (`main.rs:22`). Release builds use `panic = "abort"`. A panic in a
   request path kills the process and blinds the entire fleet. In any code reachable
   from ingest or the API: **no `unwrap`, no `expect`, no indexing, no slicing** on
   request-derived data. Use `let … else`, `match`, `get()`, `saturating_*`.
2. **Bound anything attacker-supplied before you loop on it.** Precedent:
   `MAX_EPOCH_WALK` (`main.rs:57`) exists because `epoch: u64::MAX` in an unverified
   record would spin SHA-256 forever *while holding the global lock*.
3. **Never leak K0.** It lives in `hosts/*.enroll.json` and in memory. It must never
   appear in an API response, a proof bundle, a log line, or on-chain. The entire
   forward-secrecy argument collapses if it does.
4. **No database.** This project stores everything as append-only NDJSON plus an
   in-memory index rebuilt at startup. Keep it that way — it is auditable with `cat`
   and it is what the operators expect.
5. **Do not modify the agent, the shipper, or the eBPF probe.** Everything you build is
   collector-side. The agent ships what it ships.
6. Deliberate simplifications get a `// ponytail:` comment naming the ceiling and the
   upgrade path — that is this codebase's convention (see `main.rs:214`).

## 1.6 Concurrency as it stands today — read this before designing anything

**The server must accept telemetry from many agents simultaneously. Today it accepts it
correctly but processes it one batch at a time, fleet-wide.** Fixing that is part of your
job, and it must be fixed *before* the Merkle work lands, because the Merkle work adds a
second `fsync` to the exact section that already serialises.

What is already concurrent and needs no work:

- The transport. `axum::serve` on a multi-threaded tokio runtime
  (`rt-multi-thread`, `server/edr-collector/Cargo.toml:11`) accepts and drives any number of
  simultaneous connections. Nothing about accepting N agents at once needs new plumbing.
- Per-host isolation on disk. Every host has its own `events/{host}.ndjson`,
  `hosts/{host}.state.json`, and (once you add it) `batches/{host}.ndjson`. Two different
  hosts never write the same file.
- Failure behaviour under overload. The agent's HTTP client has a 30s timeout
  (`agent/edr-agent/src/shipper.rs`, `Client::builder().timeout(...)`) and retries on the next
  poll; unshipped records stay in the WAL. So the failure mode of an overloaded collector
  is *delay and retry*, never data loss — provided you never ack what you did not store.

What is **not** concurrent, and why it matters:

```rust
struct App {
    data_dir: PathBuf,
    // ponytail: one lock over all hosts. Fine for tens of hosts at a batch
    // every few seconds; split per-host if a fleet ever makes it contend.
    hosts: Mutex<HashMap<String, Host>>,     // main.rs:216
}
```

`ingest` takes that single mutex at `main.rs:372` and holds it until `drop(hosts)` at
`main.rs:570`. Inside that span sits the **synchronous** `std::fs` append and
`f.sync_all()` at `main.rs:533-544`. Two consequences:

1. **Fleet-wide serialisation.** While host A's batch is being fsynced, host B's POST is
   parked on the mutex, as is host C's, as is the `/v1/status` handler and all three
   dashboard handlers (`dashboard.rs:222`, `:290`, `:347`). Throughput ceiling is
   `1 / fsync_latency` for the entire fleet. At a 5 ms fsync that is ~200 batches/s,
   which sounds fine — until it is a spinning disk, a contended NFS mount, or a host
   catching up after an outage.
2. **Runtime starvation.** `sync_all()` is a blocking syscall executed directly on a
   tokio worker thread. Under many concurrent agents the worker threads sit in `fsync`
   and the runtime cannot make progress on anything else — including `/healthz`, which
   then makes a healthy-but-busy collector look dead to whatever is monitoring it.

Neither is a correctness bug today. Both become one the moment you add a second fsync
per batch. §2.11 is the fix, and it is step 4 of the plan in Part 3 — do it before the
ingest hook.

---

# PART 2 — What to build

Three components, in this order. Each is independently useful; do not start the next
until the previous one has tests passing.

```
 A. Merkle batching        (in-process, edr-collector)      → batches/ + roots/
 B. Anchor worker          (separate binary, holds wallet)  → anchors/
 C. Retrieval API + verifier (dashboard socket + verify.py) → proof bundles
```

## 2.0 Why the components are split this way

The ingest-facing service must not hold a funded blockchain private key, and it must
not depend on a chain RPC being up. So the collector only *computes and stores* roots;
a separate `edr-anchor` binary reads sealed roots, submits transactions, and writes
receipts back. If the chain is unreachable for a week, ingest is unaffected and the
backlog anchors later.

## 2.1 The three-level commitment structure

```
 level 0   record line / marker line          ← the bytes stored in events/{host}.ndjson
              │ leaf hash
 level 1   BATCH  = one accepted POST         ← Merkle root over that POST's leaves
              │ "chainhash", one per batch     stored in batches/{host}.ndjson
 level 2   ROOT   = periodic, FLEET-WIDE      ← Merkle root over batch chainhashes
              │                                 stored in roots.ndjson (global)
 level 3   ANCHOR = one blockchain tx per root  stored in anchors.ndjson
```

**Level 2 is fleet-wide, not per host.** One transaction per interval regardless of how
many hosts are enrolled — otherwise anchoring cost scales with fleet size, which is the
kind of thing that looks fine with one host and becomes unaffordable with two hundred.
Cross-host leaf substitution is prevented by binding the host id into the level-2 leaf
preimage (§2.4).

Verifying one record needs `log2(records_in_batch) + log2(batches_in_root)` sibling
hashes — roughly 9 + 8 = 17 hashes for a 500-record batch inside a 256-batch root —
and **no K0**. That is what makes the proof publishable.

## 2.2 Merkle tree specification (RFC 6962 style)

Put this in a **new file `protocol/src/merkle.rs`** and declare `pub mod merkle;`
from `protocol/src/lib.rs`. It goes in the shared crate, not in the collector,
because a third-party verifier and the collector must compute identical roots —
the same reason the record format lives there. It needs no new dependency:
`sha2` is already there for the MAC.

### Hashing rules

```
leaf tags   0x00 = record leaf     0x02 = marker leaf     0x03 = batch leaf
node tag    0x01 = internal node

MTH([])      = SHA256()                       // empty tree: hash of the empty string
MTH([d])     = SHA256(0x00 || d)              // handled by the leaf fns below
MTH(D[n])    = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
               where k = largest power of two strictly less than n
```

Domain separation (the `0x00`/`0x01` prefixes) is what stops a leaf from being passed
off as an internal node. **An odd node is promoted, never duplicated** — the Bitcoin
style of duplicating the last leaf makes `[a,b,c]` and `[a,b,c,c]` produce the same
root (CVE-2012-2459). Write a test that pins this.

### API

```rust
/// SHA256(0x00 || data) — a level-0 leaf hash.
pub fn leaf(tag: u8, data: &[u8]) -> [u8; 32];
/// SHA256(0x01 || left || right)
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
/// Merkle Tree Hash over pre-computed leaf hashes.
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32];
/// Audit path for leaf `index`: (sibling_hash, sibling_is_left) bottom-up.
pub fn path(leaves: &[[u8; 32]], index: usize) -> Option<Vec<([u8; 32], bool)>>;
/// Replay a path from a leaf to a claimed root.
pub fn verify_path(leaf: [u8;32], index: usize, n: usize,
                   path: &[([u8;32], bool)], root: [u8;32]) -> bool;
fn largest_pow2_below(n: usize) -> usize;   // n>1 → 1,2,4,8,…
```

`path` returns `None` for an out-of-range index — do not panic (rule 1).

### Required tests in `merkle.rs`

- Round-trip: for every `n` in `1..=17` and every index in `0..n`,
  `verify_path(leaf_i, i, n, path(i), root)` is `true`.
- Tamper: flipping one bit in any sibling makes it `false`.
- `root([a,b,c]) != root([a,b,c,c])` (CVE-2012-2459 regression).
- Wrong index with a correct path fails.
- **Known-answer vectors**: hard-code the hex roots for `n = 1,2,3,4,8` over leaves
  `b"0".."b7"` and assert them. `verify.py` will assert the *same* constants — that is
  how you catch Rust/Python drift, which is the failure mode that costs the most time.

## 2.3 Leaf construction — the exact preimages

Get these wrong and every proof you ever issue is worthless. There are three leaf kinds.

**Record leaf (tag `0x00`)** — for a stored record line:

```
leaf(0x00, sealed_payload(&record) || hex_decode(record.hash))
```

`sealed_payload` is imported from `record.rs` — do not reimplement it. `record.hash` is
appended as its **32 raw bytes**, not as hex text. Reject the line and treat it as a
marker leaf if `hex_decode` fails (a record whose `hash` is not 64 hex chars cannot
have verified anyway).

> **Why not just hash the stored JSON line?** Because collector metadata
> (`received_at`, `segment`, `verified`) is *not* signed by the agent and is not part of
> the record. Excluding it means a third party holding only the record can recompute the
> leaf with no collector state at all. That is the whole point of the retrieval system.

**Marker leaf (tag `0x02`)** — for a `collector_event` line, hash the **exact bytes the
collector appended**, i.e. the output of `serde_json::to_string(&marker)` before the
trailing `\n`:

```
leaf(0x02, marker_json_bytes)
```

Markers are collector-authored and have no MAC, so there is nothing else to bind. Include
them anyway: a `CHAIN_BREAK` marker is the single most valuable line in the file, and if
it were left uncommitted, deleting it later would be invisible. This is a deviation from
"records only" and it is deliberate.

**Batch leaf (tag `0x03`)** — a level-2 leaf, over one batch's chainhash:

```
leaf(0x03, lp(host_id) || lp(batch_id_decimal) || chainhash_32_raw)
```

where `lp(x)` is the **same u32-big-endian length prefix used by `sealed_payload`** —
reuse the convention, do not invent a second framing. Binding `host_id` is what stops a
batch proof from being replayed against a different host now that level 2 is fleet-wide.

## 2.4 Storage schema

Three new append-only files under `--data-dir`. Every line carries `"v":1` so the format
can move later.

```
batches/{host}.ndjson   one line per accepted POST that stored ≥1 line
roots.ndjson            one line per sealed root   (global, all hosts)
anchors.ndjson          one line per blockchain tx (global) — written by edr-anchor
```

**`batches/{host}.ndjson`:**

```json
{"v":1,"batch_id":417,"host":"web-01","sealed_at":"2026-08-27T09:14:02.113Z",
 "chainhash":"9f2c…","prev_chainhash":"41ab…","count":500,
 "seq_lo":208001,"seq_hi":208500,"segment":0,
 "byte_start":78412990,"byte_end":78598123,
 "leaves":["a1b2…","c3d4…", …]}
```

- `batch_id` — per host, dense, starts at 0.
- `chainhash` — `root(leaves)`, hex.
- `prev_chainhash` — the previous batch's chainhash, `GENESIS_MAC` for `batch_id 0`.
  Chains batches the same way `prev_hash` chains records, so deleting a whole batch line
  is visible even before you reach the on-chain root.
- `byte_start` / `byte_end` — the exact byte range this batch appended to
  `events/{host}.ndjson`. Capture `byte_start` from the file length **before** the
  append; `byte_end = byte_start + out.len()`. This makes retrieval O(1) and makes
  duplicate lines from a retry harmless: the batch names bytes, not sequence numbers.
  Treat them as a **hint** on read — if the bytes at that offset do not parse or the
  recomputed leaf does not match, fall back to a linear scan and log a `CRITICAL`.
- `leaves` — every leaf hash, in order. Costs ~64 hex bytes per ~370-byte record (~17%
  storage overhead) and buys proof generation with two file reads and no re-hashing of
  the events file. Accept the trade; note it with a `ponytail:` comment.
- `count`, `seq_lo`, `seq_hi`, `segment` — index fields. Markers have no seq; if a batch
  is markers only, set `seq_lo`/`seq_hi` to `0`.
- **No `root_id` field.** Both files stay strictly append-only — nothing is ever patched
  in place. A file that is only ever appended to is one whose tampering is detectable by
  size and by chain link alone. The batch→root mapping lives in the root line.

**`roots.ndjson`:**

```json
{"v":1,"root_id":88,"sealed_at":"2026-08-27T09:20:00.004Z",
 "root":"7e91…","prev_root":"0c4d…","leaf_count":193,
 "covers":[{"host":"web-01","batch_lo":390,"batch_hi":417,"chainhashes":["9f2c…", …]},
           {"host":"db-02","batch_lo":88,"batch_hi":253,"chainhashes":[ … ]}]}
```

- Level-2 leaves are built in **deterministic order**: hosts sorted by `host_id`
  ascending (byte-wise), then `batch_id` ascending within a host. Flatten to a single
  leaf vector in that order. Write the ordering rule as a comment and as a test — a
  verifier that sorts differently computes a different root and every proof fails.
- `prev_root` chains roots; `GENESIS_MAC` for `root_id 0`.
- `chainhashes` are stored so proof generation needs no recomputation.

**`anchors.ndjson`** — see §2.7.

## 2.5 In-memory index

Rebuild at startup, extend live. No database, no persistence beyond the NDJSON files.

```rust
struct BatchIndexEntry { batch_id: u64, seq_lo: u64, seq_hi: u64, segment: u64,
                         byte_start: u64, byte_end: u64, count: u32,
                         sealed_at: DateTime<Utc>, line_offset: u64 }

struct MerkleIndex {
    // per host, ordered by batch_id (== insertion order)
    batches: HashMap<String, Vec<BatchIndexEntry>>,
    // ordered by root_id
    roots: Vec<RootIndexEntry>,      // root_id, sealed_at, line_offset, covers ranges
    anchors: HashMap<u64, AnchorIndexEntry>,  // root_id → tx
    pending: Vec<(String, u64)>,     // (host, batch_id) sealed but not yet in a root
}
```

`line_offset` is the byte offset of that line within its own NDJSON file, so a proof
request reads exactly one line instead of the whole file. Loading is a single sequential
pass per file at startup; at 500 records/batch a year of one busy host is ~60k batch
lines — well within a startup scan, and `leaves[]` is **not** kept in memory, only the
offset. Add a `ponytail:` comment: full-scan startup, add a checkpoint file if boot time
becomes noticeable.

Store the index behind its **own** `tokio::sync::Mutex`, separate from the per-host
locks. It is the one piece of Merkle state that is genuinely shared across hosts, so it
is the one place many agents contend. Keep every critical section on it to pure in-memory
work — no file I/O, no hashing of a whole batch, no `.await` on anything but the lock
itself. Cache each pending batch's `chainhash` in the `pending` entry so the root sealer
never needs to reach back into a host's files (or its lock) to build a root; that is what
keeps the lock graph acyclic. Lock ordering is specified in §2.11 and is not optional.

## 2.6 Hooking into ingest

Modify `async fn ingest` in `server/edr-collector/src/main.rs:357`. Ordering is the whole
correctness argument; follow it exactly.

1. **Before the loop**: `let mut pending_leaves: Vec<[u8;32]> = Vec::new();` alongside
   the existing `let mut out = String::…`.
2. **Every time a line is pushed into `out`** — and there are three such places: the
   `BUILD_MISMATCH` marker (`main.rs:442`), the `CHAIN_BREAK` marker (`main.rs:505`),
   and the `StoredRecord` (`main.rs:521`) — push the corresponding leaf into
   `pending_leaves` in the same order. Ordering must match the bytes exactly. The
   cleanest way to guarantee that is a tiny local closure that takes the JSON string,
   pushes it to `out`, and pushes the leaf; use it at all three sites so a future line
   type cannot be added to one without the other.
3. **Capture `byte_start`** immediately before the append, from the opened file's
   metadata length (`main.rs:539` region). If the file does not exist yet, `0`. This
   read must happen under the same per-host lock as the append, or two concurrent
   writers to one host would both claim the same offset.
4. **Append events and `sync_all()` first** (existing code, `main.rs:533-559`), moved
   into `spawn_blocking` per §2.11. If it fails: discard `pending_leaves`, restore
   `pre_batch`, return 500 — unchanged behaviour.
5. **Only if the append succeeded and `pending_leaves` is non-empty**: compute
   `chainhash = merkle::root(&pending_leaves)`, build the batch line, append it to
   `batches/{host}.ndjson` and `sync_all()`.
   - If the batch append fails: log `CRITICAL`, **restore `entry.state = pre_batch`**,
     and return 500 without acking. The agent retries; the retried records get appended
     to the events file a second time (duplicates), and the second attempt commits those
     bytes. Because batches name byte ranges, the orphaned first copy is simply
     uncommitted bytes — never a corrupt proof. Add exactly this reasoning as a comment;
     the next reader will otherwise "fix" it into a bug.
6. Update the in-memory index and `pending` list. Still holding the **per-host** lock,
   take the **index** lock, push the entry (including its `chainhash`), release the index
   lock. That is the mandated lock order — host, then index, never the reverse (§2.11).
7. Existing tail: `last_seen`, drop lock, `save_state`, respond.

Cost inside the per-host lock: one SHA-256 per record plus n−1 for the tree —
microseconds for a 500-record batch, versus two `fsync`s in the same section. Acceptable.
Do **not** do anything network-bound, cross-host, or root-sealing-related inside it.

New `HostState` fields, all `#[serde(default)]`:

```rust
batches: u64,            // next batch_id
last_chainhash: String,  // GENESIS_MAC when none
last_committed_seq: u64,
```

## 2.7 The root sealer task

A `tokio::spawn` alongside `watch_for_silence` (`main.rs:618` is the pattern to copy,
including how it takes `Arc<App>` and how it avoids holding the lock across I/O).

New `serve` flags:

```
--root-interval-secs 600     # seal a root at least this often, if anything is pending
--root-max-batches   256     # …or as soon as this many batches are pending
--merkle off|on              # default on; `off` disables batching entirely
```

Loop, once per 10s tick:

1. Lock the index — **and only the index; the sealer must never take a host lock**, which
   is what keeps it off the ingest path and the lock graph acyclic. Take the `pending`
   list if `pending.len() >= root_max_batches` or `now - last_seal >= root_interval_secs`;
   **clone what you need and release the lock immediately**.
2. For each pending `(host, batch_id, chainhash)` — the chainhash was cached at ingest
   precisely so this step needs no host lock and no file read — group by host, sort hosts
   ascending, batches ascending, build level-2 leaves per §2.3, compute the root. All of
   this happens with **no lock held**.
3. Append the root line to `roots.ndjson`, `sync_all()`.
4. Re-lock, clear the sealed entries from `pending`, update the root index.
5. If the append failed, **do not clear `pending`** — the same batches roll into the
   next attempt. Sealing is idempotent in effect: a root that was never written simply
   never existed.

Seal nothing when `pending` is empty. A quiet fleet must not produce empty roots and must
not spend gas.

## 2.8 Component B — the anchor worker (`edr-anchor`)

A **new binary crate `server/edr-anchor/`**, added to the `members` list in
`server/Cargo.toml`. It belongs to the server workspace and must never be
reachable from `agent/`. It is the only thing in this repository that touches a private key or
a chain RPC. It reads `roots.ndjson` and appends to `anchors.ndjson`; it never reads
`hosts/` and must have no filesystem access to K0 (document this in the systemd unit /
README you write).

### Chain and transaction format

Default to an **EVM L2** (Base, Arbitrum, Optimism, or Polygon PoS). Rationale: cheap,
public, dozens of independent RPC endpoints and explorers a verifier can use, and the
tooling is mature. Make chain id, RPC URL and the anchoring account configurable so a
private chain or a testnet works unchanged.

**Do not deploy a contract.** Anchor by sending a 0-value transaction **from the anchor
account to itself**, with the payload in calldata:

```
calldata = "EDRMR1" (6 ASCII bytes) || root_32_bytes || root_id_u64_be
```

Calldata is permanently retrievable via `eth_getTransactionByHash` on any archive node,
costs 16 gas per non-zero byte, and needs no ABI, no deployment, no upgrade story, and
no contract risk. A verifier fetches the tx and compares 32 bytes.

Offer a contract only as an option, and only if the operator explicitly wants roots
queryable on-chain by index or wants an indexed event log:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract EDRAnchor {
    event Root(uint64 indexed rootId, bytes32 root, uint64 timestamp);
    address public immutable notary;
    constructor() { notary = msg.sender; }
    function anchor(uint64 rootId, bytes32 root) external {
        require(msg.sender == notary, "not notary");
        emit Root(rootId, root, uint64(block.timestamp));
    }
}
```

Anything more than this — storing roots in contract storage, access-control lists,
upgradeability — is spending real money and real audit surface on a feature nobody asked
for. Calldata is the default; the contract is opt-in behind `--contract 0x…`.

**Never put record data, host names, counts, or timestamps beyond the root on-chain.**
Everything on a public chain is public forever. The root is 32 bytes of hash and reveals
nothing; a host name reveals your fleet inventory.

### Rust libraries

`alloy` (successor to ethers-rs) for signing and RPC. Keep it in `edr-anchor` only — do
not add a chain dependency to `edr-collector`, `edr-record`, or the agent — a dependency
added to `protocol/` lands in the agent binary too. Match
the existing TLS choice: `rustls`, not the system OpenSSL (see the `reqwest` comment in
`edr-agent/Cargo.toml`).

For a first end-to-end smoke test before writing any Rust, `cast` from Foundry does the
whole job in one line — use it to prove the flow, then implement the worker:

```bash
cast send --private-key $KEY --rpc-url $RPC $SELF_ADDR \
  "0x$(printf '4544524d5231'; echo -n $ROOT_HEX; printf '%016x' $ROOT_ID)"
```

### Crash-safe submission — record intent before broadcasting

The failure to design against: the worker broadcasts, crashes before recording the tx
hash, restarts, and anchors the same root again from a different nonce — burning gas and
producing two conflicting anchors.

Two-phase, both phases appended to `anchors.ndjson`:

```json
{"v":1,"phase":"submitted","root_id":88,"root":"7e91…","chain_id":8453,
 "from":"0xabc…","nonce":1204,"tx":"0x5f…","submitted_at":"2026-08-27T09:20:11Z"}
{"v":1,"phase":"confirmed","root_id":88,"root":"7e91…","chain_id":8453,
 "tx":"0x5f…","block_number":21883014,"block_hash":"0x77…",
 "block_time":"2026-08-27T09:20:37Z","confirmations":12,
 "confirmed_at":"2026-08-27T09:24:02Z"}
```

Algorithm:

1. On start, scan `anchors.ndjson`; any `submitted` without a matching `confirmed` is
   **in flight**.
2. For each in-flight entry, query the tx by hash. Confirmed → append `confirmed`.
   Unknown/dropped → **resubmit with the same `nonce`**, never a fresh one. Same nonce
   means at most one of the two can ever land.
3. Only then look for unanchored roots (`root_id` present in `roots.ndjson`, absent from
   `anchors.ndjson`), oldest first, one at a time.
4. Write the `submitted` line and `sync_all()` **before** calling `eth_sendRawTransaction`.
5. Poll until `--confirmations` (default 12; on a fast L2 use 20+) then write `confirmed`.
6. Reorg: if a previously-confirmed tx no longer resolves, append a
   `{"phase":"reorged", …}` line and re-anchor as a new submission. Never rewrite a line.

Retry with exponential backoff, cap it, and log `CRITICAL` on sustained failure. An
anchoring outage is a monitoring event, not a data-loss event — roots keep accumulating
and anchor later. Surface `roots_unanchored` and `oldest_unanchored_age_secs` in the
retrieval API so a stuck worker is visible.

### Key handling

- Private key from a file with mode `0600` or from an env var, never a CLI arg
  (`/proc/*/cmdline` is world-readable). Follow the permission checks in
  `agent/edr-agent/src/main.rs:225` (`prepare_wal_dir`) for the pattern: refuse to start on a
  symlink, refuse on group/world-writable, `O_NOFOLLOW`.
- The account needs only gas. Fund it with a small float and alert on low balance —
  expose `anchor_balance_wei` in the API.
- Run as a separate unix user from the collector. It only needs read on `roots.ndjson`
  and append on `anchors.ndjson`.

### Cost

One tx per root. At `--root-interval-secs 600` that is 144 tx/day. Calldata is 46 bytes
plus 21,000 base gas ≈ 21.7k gas. On an L2 at typical fees this is a fraction of a cent
per transaction — order of a few dollars a year. **Verify current gas prices yourself
before quoting a number to the operator**; these figures move. If cost is a concern the
knob is `--root-interval-secs`, and the cost/latency trade is linear: 3600s is 24 tx/day
with up to a one-hour worst-case proof latency.

## 2.9 Component C — the retrieval system

All read endpoints go on the **dashboard socket** (`dashboard.rs:56` router), never the
ingest socket. The ingest socket is reachable by an untrusted proxy; proof endpoints
enumerate records and must not be.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/merkle/status` | index summary: batches, roots, pending, unanchored count + age, last anchor tx, chain id |
| `GET /api/merkle/record?host=H&seq=N[&segment=S]` | **the primary one** — full proof bundle for one record |
| `GET /api/merkle/records?host=H&from_seq=A&to_seq=B[&severity=][&limit=]` | bulk retrieval, `include_proof=true` optional |
| `GET /api/merkle/batch/{host}/{batch_id}` | batch metadata + its leaves + its root/anchor |
| `GET /api/merkle/roots?limit=&before_id=` | recent roots with anchor status |
| `GET /api/merkle/root/{root_id}` | one root, its covers list, its anchor |
| `GET /api/merkle/tx/{tx_hash}` | reverse lookup: which root, which hosts, which seq ranges |
| `GET /api/merkle/audit?host=H` | self-check: recompute every chainhash from the events file and every root from the chainhashes; report mismatches |

Rules for all of them: cap `limit` (`MAX_LIMIT` pattern already exists in
`dashboard.rs`), validate `host` with the existing `valid_host_id`, return
`404`/`400` as JSON rather than panicking, and set the same security headers the
existing dashboard handlers set (`dashboard.rs:65` — CSP, `Cache-Control: no-store`).

If `(host, seq)` matches more than one record (different segments, or a forced
re-enrollment), return **all** matches as an array with their segments rather than
guessing. Document it in the response.

### The proof bundle — response schema

This is the artifact the whole feature exists to produce. It must be verifiable by
someone with **no access to this server** and **no K0**.

```json
{
  "v": 1,
  "record": { "seq": 208137, "epoch": 4211, "…": "…", "hash": "…" },
  "collector_metadata": { "received_at": "…", "segment": 0, "verified": true,
                          "host": "web-01" },
  "leaf": { "tag": "0x00", "hash": "a1b2…",
            "preimage_rule": "SHA256(0x00 || sealed_payload(record) || raw(record.hash))" },
  "batch": {
    "host": "web-01", "batch_id": 417, "count": 500, "index": 136,
    "chainhash": "9f2c…", "prev_chainhash": "41ab…", "sealed_at": "…",
    "path": [{"h":"…","left":true},{"h":"…","left":false}, "…"]
  },
  "root": {
    "root_id": 88, "root": "7e91…", "prev_root": "0c4d…",
    "leaf_count": 193, "index": 41, "sealed_at": "…",
    "batch_leaf": "c0ff…",
    "batch_leaf_rule": "SHA256(0x03 || lp(host) || lp(batch_id) || raw(chainhash))",
    "path": [{"h":"…","left":false}, "…"]
  },
  "anchor": {
    "status": "confirmed",
    "chain_id": 8453, "chain_name": "base",
    "tx": "0x5f…", "block_number": 21883014, "block_hash": "0x77…",
    "block_time": "2026-08-27T09:20:37Z", "confirmations": 12,
    "calldata_rule": "0x4544524d5231 || root(32) || root_id(u64 be)",
    "verify_with": "eth_getTransactionByHash on any Base RPC; compare bytes 6..38 of input"
  },
  "claims": [
    "This record's bytes were committed to root 7e91… before block 21883014.",
    "Block 21883014 was mined at 2026-08-27T09:20:37Z (per the chain)."
  ],
  "not_claims": [
    "This does NOT prove the record is authentic; that requires the HMAC under the escrowed K0.",
    "This does NOT prove when the traced event occurred, only when the commitment was published.",
    "This does NOT prove no record was omitted before batching."
  ]
}
```

Emit `claims`/`not_claims` verbatim in every bundle. A proof that gets over-read in an
incident report is a liability.

When the root is not yet anchored, return `"status":"pending"` with the sealed root and
`"anchored_by": null` — the bundle is still useful (it is a commitment the server cannot
retroactively change without breaking `prev_root`), just not yet independently timestamped.

### Lookup algorithm

1. Validate `host`; look up `batches[host]`; binary-search for the entry with
   `seq_lo <= seq <= seq_hi` (and matching `segment` if given). Multiple hits → return
   all. No hit → `404`.
2. Read `events/{host}.ndjson` over `[byte_start, byte_end)`; split lines; find the one
   whose `record.seq == seq`. Track its **line index within the batch** — that index is
   the Merkle leaf index and must count *all* committed lines including markers.
3. Recompute the leaf from the record and assert it equals `batch.leaves[index]`. If it
   does not, **do not serve the proof** — return `500`, log `CRITICAL: collector store
   diverges from its own commitment at host/seq`. That mismatch is precisely the
   tampering the feature detects, and hiding it behind a plausible-looking proof would be
   the worst possible outcome.
4. `path = merkle::path(&batch.leaves, index)`.
5. Find the root whose `covers` includes `(host, batch_id)`; rebuild the level-2 leaf
   vector in the canonical order (§2.4); locate the index of this batch's leaf;
   `path = merkle::path(&level2_leaves, index)`.
6. Look up the anchor by `root_id` in `anchors.ndjson`; take the newest non-`reorged`
   phase.
7. Assemble and return.

### CLI subcommands

Mirror every API capability on the CLI — the existing `verify`/`status` subcommands set
that expectation, and an incident responder on a box with no browser needs them.

```
edr-collector merkle-status
edr-collector merkle-proof --host H --seq N [--out proof.json]
edr-collector merkle-audit [--host H]      # recompute everything from events/, report drift
edr-collector merkle-verify --proof proof.json [--rpc-url URL]
```

`merkle-audit` is the one an auditor runs: it re-derives every chainhash from the actual
bytes in `events/{host}.ndjson` and every root from those chainhashes, and prints
`intact` / a list of divergences — the same output shape as the existing `cmd_verify`
(`main.rs:808-820`), which prints a small table ending in a `RESULT` line. Match that
style.

## 2.10 Extending `verify.py`

`verify.py` at the repo root is the standalone offline verifier (350 lines, stdlib only,
no third-party imports — keep it that way). Today it verifies the HMAC chain given K0.
Add a **second, independent mode** that verifies a proof bundle with no K0:

```
verify.py --proof proof.json [--expect-root 7e91… | --rpc-url https://…]
verify.py --selftest        # existing; extend it
```

Add these functions, mirroring `merkle.rs` exactly:

```python
def _leaf(tag, data):  return hashlib.sha256(bytes([tag]) + data).digest()
def _node(l, r):       return hashlib.sha256(b"\x01" + l + r).digest()
def merkle_root(leaves): …          # RFC 6962, odd node promoted
def verify_path(leaf, index, n, path, root): …
def _lp(v): return struct.pack(">I", len(v)) + v   # already present as a helper
```

The bundle check, in order — report each step pass/fail rather than a single boolean:

1. Recompute `leaf` from `record` using the existing `sealed_payload()` plus
   `bytes.fromhex(record["hash"])`; compare to `bundle.leaf.hash`.
2. Replay `batch.path` from the leaf at `batch.index` over `batch.count` leaves; compare
   to `batch.chainhash`.
3. Recompute the batch leaf: `_leaf(0x03, _lp(host) + _lp(str(batch_id)) + bytes.fromhex(chainhash))`;
   compare to `root.batch_leaf`.
4. Replay `root.path` from `root.index` over `root.leaf_count`; compare to `root.root`.
5. If `--expect-root` given, compare. If `--rpc-url` given, do a single
   `eth_getTransactionByHash` POST with `urllib.request` (stdlib), slice bytes 6..38 of
   `input`, and compare — plus check the tx `to == from` and the block number matches.
6. Print the `not_claims` from the bundle so the operator reads them.

Extend `--selftest` with the same known-answer vectors as the Rust tests. Drift between
the two implementations is the most likely bug in this whole feature and the KATs are the
only thing that catches it cheaply.

## 2.11 Concurrency: many agents reporting at once

Read §1.6 first. Design target: **hundreds of enrolled hosts, each POSTing a batch of up
to 500 records every 5 seconds** (the agent defaults, `agent/edr-agent/src/main.rs:78-83`), plus
several hosts at a time catching up after an outage at the full 16 MB body limit. That is
tens of POSTs per second, each ending in two fsyncs.

### 2.11.1 Split the global lock per host

Replace the single map-wide mutex with a mutex per host. The outer lock then guards only
registry lookup and insertion — microseconds, no I/O — and the inner lock guards one
host's chain state and its files.

```rust
struct App {
    data_dir: PathBuf,
    /// Registry only. Held just long enough to clone an Arc. Never held across I/O.
    hosts: Mutex<HashMap<String, Arc<Mutex<Host>>>>,
    /// Cross-host Merkle state (§2.5). Pure in-memory critical sections.
    merkle: Mutex<MerkleIndex>,
}
```

The access pattern, and the only correct one:

```rust
// 1. short outer critical section: find or lazily load the host, clone the Arc
let host_entry: Arc<Mutex<Host>> = {
    let mut reg = app.hosts.lock().await;
    match reg.get(&host) {
        Some(h) => Arc::clone(h),
        None => { /* load_enrollment + parse_key + load_state, or return 403 */ }
    }
};                                   // <-- outer guard dropped HERE
// 2. everything else happens under this host's own lock
let mut entry = host_entry.lock().await;
```

Never hold the outer guard across the inner `.lock().await`, and never across file I/O.
Write that as a comment on the field; it is the invariant the whole refactor rests on.

**Keep `tokio::sync::Mutex`, not `std::sync::Mutex`.** The guard is held across `.await`
points (the `spawn_blocking` in §2.11.3), which a `std` guard cannot legally do.

**Why per-host locking is required, not just faster:** everything the lock protects is
per-host chain state — `high_seq`, `last_mac`, `segment`, `batch_id`, the append offset
into that host's own files. Two concurrent POSTs *for the same host* must serialise or
they will interleave bytes in `events/{host}.ndjson`, duplicate a `batch_id`, and race on
`byte_start`. Two POSTs for *different* hosts share nothing and must not block each other.
A per-host mutex expresses exactly that and nothing more.

Same-host concurrency is rare but real: the agent ships one batch per poll from a single
task, but a retry after a client-side timeout can overlap the request still executing on
the server, and two misconfigured agents can present the same `X-EDR-Host`. Both cases are
handled correctly by serialising: the second one's records are skipped by the existing
`rec.seq <= high_seq` replay check, or produce a `CHAIN_BREAK` — which is detection, not
corruption. Host identity is a claim; what authenticates a host is that its records verify
under its escrowed K0.

### 2.11.2 Lock ordering

Exactly one order is legal. Violating it deadlocks the collector, and `panic = "abort"`
means a deadlocked collector blinds the whole fleet.

```
app.hosts (registry)  →  Host (per-host)  →  app.merkle (index)
```

- `ingest`: registry (brief) → host → merkle (brief). Legal.
- root sealer: merkle only. Legal — never takes a host lock (§2.7), which is why there is
  no cycle.
- retrieval API: registry (brief, to validate the host exists) → merkle (brief, to read
  index entries). It reads records from the events file by byte offset **without** the
  host lock — the file is append-only, so a concurrent append can only add bytes past
  the range being read.
- `watch_for_silence` (`main.rs:618`): registry → host, one host at a time, releasing
  between hosts. Do not hold the registry lock across the whole sweep.

Add a comment block stating this order above the `App` struct. Anyone adding a handler
later needs to find it without re-deriving it.

### 2.11.3 Get blocking I/O off the runtime threads

Both fsyncs — the events append and the batch append — must run in
`tokio::task::spawn_blocking`, not inline. Precedent already exists in this codebase:
`dashboard.rs:246` and `read_pending` in `agent/edr-agent/src/shipper.rs` both do exactly this
for file work.

```rust
let path = events_path(&app.data_dir, &host);
let bytes = std::mem::take(&mut out);
let append = tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
    // open O_APPEND, stat for byte_start, write_all, sync_all
}).await;
let (byte_start, byte_end) = match append {
    Ok(Ok(v)) => v,
    Ok(Err(e)) => { /* CRITICAL, restore pre_batch, 500 without ack */ }
    Err(join) => { /* the blocking task panicked or was cancelled: same path */ }
};
```

The per-host guard stays held across this `.await` — that is intended and correct, and it
is why the mutex must be tokio's. Handle the `JoinError` arm explicitly; do not `unwrap`
the join (rule 1).

The blocking pool defaults to 512 threads, so dozens of simultaneous fsyncs are absorbed
without touching the worker threads that serve `/healthz` and the dashboard.

### 2.11.4 Admission control

With N agents in flight the collector buffers N request bodies at once, each up to
`MAX_BODY_BYTES` (16 MB, `main.rs:49`). Two hundred catching-up agents is 3.2 GB of
`String` — an OOM that a `panic = "abort"` build turns into a fleet-wide blackout.

Add a global semaphore on the ingest handler:

```
--max-concurrent-ingest 32     # new `serve` flag; tokio::sync::Semaphore
```

Acquire before reading the body; on `try_acquire` failure return **`503` with
`Retry-After`**, never a 4xx. The agent treats non-2xx/409 as a transient failure, keeps
the records in its WAL, and retries on the next poll — so shedding load here costs
nothing but latency. Do not return 409 under load: the shipper advances its cursor past a
409, which would drop records on the floor for the one reason that has nothing to do with
tampering.

Also cap the total: `max_concurrent_ingest * MAX_BODY_BYTES` is your worst-case ingest
memory. Pick the default so that product is a few hundred MB, and say so in the flag's
help text.

### 2.11.5 Two more sharp edges

- **Unenrolled-host spray.** Every POST with an unknown `X-EDR-Host` currently costs a
  filesystem `read_to_string` miss on the registry path (`main.rs:378`). An attacker who
  can reach the ingest port turns that into disk load with no valid credential. Add a
  small negative cache (bounded LRU or a `HashSet` capped at a few thousand entries,
  cleared on enrollment) so repeated unknown ids are refused from memory. `valid_host_id`
  already blocks path traversal; this is about cost, not escape.
- **Readers versus writers.** The dashboard handlers take the registry lock at
  `dashboard.rs:222`, `:290` and `:347`. After the refactor they should clone host names
  or Arcs under the outer lock and release it immediately; the alert/overview data itself
  comes from tailing the events files, which needs no host lock at all. Do not let a
  read-only dashboard request sit behind an ingest fsync.

### 2.11.6 Concurrency tests you must write

Use `#[tokio::test(flavor = "multi_thread")]` and drive the real `ingest` handler.

- **N hosts in parallel**: 50 hosts × 10 concurrent batches each. Assert every batch is
  acked, every `events/{host}.ndjson` parses line-by-line with no interleaved or partial
  lines, every host's `batch_id` sequence is dense from 0, and `merkle-audit` recomputes
  every chainhash and root as intact.
- **Same host in parallel**: 8 concurrent identical batches for one host. Assert exactly
  one is stored, the other seven are no-ops via the replay check, and **exactly one batch
  line** is written (empty `pending_leaves` seals nothing).
- **Same host, different records, in parallel**: assert serialisation — no duplicate
  `batch_id`, no overlapping `[byte_start, byte_end)` ranges, and the union of committed
  ranges has no gaps that contain a stored line.
- **Root sealing under load**: keep ingesting while the sealer fires; assert no root
  omits a batch that was acked before the seal, and no batch appears in two roots.
- **Overload**: exceed `--max-concurrent-ingest`; assert 503 (not 409, not 500) and that
  a retry of the shed batch succeeds and is committed.
- **Deadlock guard**: run the full parallel suite under a wall-clock timeout so a lock
  inversion fails the test instead of hanging CI.

---

# PART 3 — Execution plan

Do these in order. Each step ends with something runnable and tested; do not batch them.

| # | Step | Done when |
|---|---|---|
| 1 | Read `protocol/src/lib.rs` and `server/edr-collector/src/main.rs:328-581` in full | you can state from memory what happens to a record that fails its MAC |
| 2 | `protocol/src/merkle.rs` + tests + KATs | `cargo test -p edr-record` green, including `n=1..17` round-trip and the CVE-2012-2459 case |
| 3 | Merkle KATs in `verify.py --selftest`, same constants | `python3 verify.py --selftest` green; hex constants identical to step 2 |
| 4 | **Concurrency refactor (§2.11): per-host locks, `spawn_blocking` fsync, ingest semaphore** | 50 hosts POSTing in parallel all commit correctly; `/healthz` still answers under sustained load; existing collector tests green. **No Merkle code yet — land this alone.** |
| 5 | Batch storage + ingest hook (§2.6) + `HostState` fields | POST a batch, see `batches/{host}.ndjson` grow; concurrency suite from step 4 still green; state files from before your change still load |
| 6 | `merkle-audit` CLI | recomputes every chainhash from `events/` and prints `intact` on real data |
| 7 | Root sealer task + `roots.ndjson` | roots seal on both triggers; empty fleet seals nothing; `prev_root` chains; sealing under concurrent ingest loses no batch |
| 8 | Retrieval API + proof bundle + `merkle-proof` CLI | bundle for a real record verifies with `verify.py --proof` (no K0, no RPC); proof requests do not stall behind ingest |
| 9 | `edr-anchor` against a **testnet** first | root anchored, `submitted`→`confirmed` in `anchors.ndjson`, bundle carries the tx |
| 10 | `verify.py --proof --rpc-url` end-to-end | third-party verification against the public RPC passes |
| 11 | Dashboard surfacing | anchor status + unanchored age visible in the UI; restart-crash test on the anchor worker produces no duplicate anchor |

Step 4 is sequenced before the Merkle work on purpose. It is a mechanical refactor with
no format implications, it is independently testable, and landing it separately means that
if a lock inversion shows up you know it came from the refactor and not from the
commitment logic.

## Acceptance tests to write

- **Tamper detection**: edit one byte of a record in `events/{host}.ndjson`;
  `merkle-audit` must report the divergence and the proof endpoint for that record must
  return 500, not a proof.
- **Deletion detection**: delete a whole line; the batch chainhash recomputation fails.
- **Batch deletion**: delete a batch line; `prev_chainhash` continuity breaks.
- **Root deletion**: delete a root line; `prev_root` continuity breaks and the anchored
  root has no covering line — report it loudly.
- **Marker commitment**: force a chain break (ship a record with a bad `prev_hash`),
  confirm the `CHAIN_BREAK` marker is a committed leaf and is provable.
- **Idempotent replay**: re-POST an identical batch; records are skipped by the existing
  `seq <= high_seq` check, so **no second batch line is written** (`pending_leaves` is
  empty → nothing sealed). Assert this explicitly; it is easy to get wrong.
- **Crash between append and batch write**: simulate; assert no proof is ever served for
  uncommitted bytes.
- **Anchor restart mid-flight**: kill after `submitted`, restart, assert same nonce is
  reused and exactly one tx lands.
- **Backward compat**: an old `hosts/{host}.state.json` with no Merkle fields loads and
  starts at `batch_id 0`.
- **Concurrency**: the full suite in §2.11.6 — parallel hosts, parallel same-host,
  sealing under load, overload shedding, and a wall-clock deadlock guard.
- **Liveness under load**: with all 50 simulated hosts ingesting, `/healthz` and the
  dashboard endpoints answer within a bounded time. A collector that stops answering its
  own health check under normal fleet load is a failed build, not a slow one.

## Things not to do

- Do not modify `sealed_payload`, `SEALED_FIELDS`, `AgentLog`, the key schedule, the
  agent, the shipper, or the eBPF probe.
- Do not put record content, host names, or K0 on-chain. Roots only.
- Do not add a database, a message queue, or a cache layer. NDJSON + in-memory index.
- Do not make the collector depend on the chain being reachable. Ingest must never block
  on an RPC.
- Do not put proof endpoints on the ingest socket.
- Do not duplicate the last leaf for odd node counts.
- Do not serve a proof when the recomputed leaf disagrees with the stored one. Fail loudly.
- Do not hold the registry mutex across any file I/O, network call, `.await` on another
  lock, or root-sealing work. Obey the lock order in §2.11.2.
- Do not run `sync_all()` on a tokio worker thread. `spawn_blocking`, always.
- Do not swap `tokio::sync::Mutex` for `std::sync::Mutex` — the guards are held across
  `.await`.
- Do not shed load with a 409. The shipper advances past a 409 and the records are gone.
  Overload is `503` + `Retry-After`.
- Do not serialise different hosts against each other for any reason. If you find yourself
  needing a fleet-wide lock on the ingest path, the design is wrong.
- No `unwrap`/`expect`/indexing on request-derived data anywhere in the request path —
  including `JoinError` from `spawn_blocking`.

## Open decisions to put to the operator before step 9

1. **Which chain and which RPC provider** (Base / Arbitrum / Optimism / Polygon /
   private). Affects confirmation depth and cost.
2. **Anchoring cadence** — `--root-interval-secs`, trading gas cost against worst-case
   proof latency.
3. **Calldata vs contract.** Default calldata; the contract is only worth it if roots
   must be queryable on-chain.
4. **Who funds and rotates the anchor account**, and what the low-balance alert path is.
5. **Retention.** `events/*.ndjson` currently grows without bound and there is no
   rotation. Once roots are anchored, old events can be archived off-box while their
   proofs stay valid — but any archived range must remain retrievable or the retrieval
   API will 404 on it. Decide the policy before the disk decides it for you.
