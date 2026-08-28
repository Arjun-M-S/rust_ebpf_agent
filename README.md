# edr — a Linux EDR agent and its off-box collector

Two standalone components that talk to each other over HTTP, plus the wire
contract they share.

```
protocol/   edr-record — the sealed record format and its MAC. The one thing
            both halves must agree on byte-for-byte. Depended on by path from
            each side so it cannot drift.

agent/      the endpoint half. eBPF probe on sched_process_exec, forward-secure
            sealing, write-ahead log, shipper. Needs nightly + bpf-linker to
            build and root to run.
            └─ edr-agent, edr-agent-ebpf, edr-agent-common (kernel ABI)

server/     the off-box half. Verifies each shipped record against the host's
            escrowed K0, appends it to an NDJSON store, commits every accepted
            batch to a Merkle tree, serves the analyst dashboard and the proof
            retrieval API. Stable toolchain, no eBPF, no root.
            ├─ edr-collector — ingest, storage, commitments, dashboard, proofs
            └─ edr-anchor    — publishes periodic roots to a blockchain. The
               only component that holds a private key or reaches a chain, and
               a separate binary and unix user for exactly that reason.

verify.py   standalone offline verifier, stdlib only. Mirrors protocol/ by hand.
            Two modes: --key checks authenticity against K0; --proof checks a
            commitment with no K0 and no access to the collector at all.
```

Each of `agent/`, `server/` and `protocol/` is its own cargo workspace with its
own lockfile and its own `.cargo/config.toml`. Building or testing one never
compiles the other — that split is deliberate: the server is expected to be
deployed, updated and audited on its own schedule, and nothing about it should
require a kernel-tracing toolchain.

## Build

```shell
cd server && cargo build --release && cargo test    # stable, unprivileged
cd agent  && cargo build --release                  # nightly + bpf-linker
cd protocol && cargo test                           # the shared format
```

## Run

```shell
# server
./server/target/release/edr-collector --data-dir ./data enroll --host web-01 --key $K0
./server/target/release/edr-collector --data-dir ./data serve \
    --listen 0.0.0.0:8080 --dashboard-listen 127.0.0.1:8081

# agent (on the monitored host, as root)
./agent/target/release/edr-agent --collector-url http://collector:8080 --host-id web-01
```

## The contract between them

Everything crossing the boundary is here. Change it in `protocol/` or not at all.

**Agent → server.** `POST /v1/ingest`, `content-type: application/x-ndjson`,
one sealed `AgentLog` per line, ≤ 16 MB.

| Header | Meaning |
|---|---|
| `X-EDR-Host` | enrolled host id; also the filename under `events/`, so it is validated |
| `X-EDR-Build` | agent build id; a mismatch against enrollment raises a `BUILD_MISMATCH` marker |

| Response | Agent behaviour |
|---|---|
| `200 {"acked_seq":N}` | advance the WAL cursor past N |
| `409 {"acked_seq":N,"error":…}` | advance anyway — the evidence is off-box, wedging would blind the collector to everything after |
| anything else | keep the records in the WAL, retry on the next poll |

The agent never blocks on the server: unshipped records stay in the write-ahead
log, so the failure mode of an unreachable or overloaded collector is delay,
never data loss.

**Server, read-only.** `GET /v1/status`, `GET /healthz` on the ingest socket;
`GET /`, `/api/overview`, `/api/alerts`, `/api/host/{host}` and the retrieval
API (`/api/merkle/status`, `/api/merkle/record`, `/api/merkle/records`,
`/api/merkle/batch/{host}/{id}`, `/api/merkle/roots`, `/api/merkle/root/{id}`,
`/api/merkle/tx/{hash}`, `/api/merkle/audit`) on a **separate** dashboard socket
that must never be reachable from the agent side. Proof endpoints enumerate
records, so they belong on the analyst side with everything else that does.

**Anyone, given a proof bundle.** A bundle from `/api/merkle/record` or
`edr-collector merkle-proof` is checkable with no K0, no collector and no
credential:

```shell
verify.py --proof proof.json                          # hashes only, offline
verify.py --proof proof.json --rpc-url https://…      # …and against the chain
```

It proves those exact record bytes were committed to a root published on chain
before a given block. It does not prove the record is authentic (that is the
HMAC under K0), does not prove when the event happened, and cannot see a record
dropped before it was ever batched. Every bundle carries those three limits
verbatim.

**Out of band.** The root key `K0` is escrowed on the server by
`edr-collector enroll` and never crosses the network in either direction.

`server.md` specifies the Merkle-batching, blockchain-anchoring and proof
retrieval layer; `server/edr-anchor/README.md` covers deploying the anchor
worker, including the unix isolation that keeps it away from K0.

## License

Dual MIT / Apache-2.0, except the eBPF code under `agent/edr-agent-ebpf`, which
is dual GPL-2 / MIT. See [LICENSE-MIT], [LICENSE-APACHE], [LICENSE-GPL2].

[LICENSE-MIT]: LICENSE-MIT
[LICENSE-APACHE]: LICENSE-APACHE
[LICENSE-GPL2]: LICENSE-GPL2
