# edr-anchor

Publishes the collector's periodic Merkle roots to a blockchain.

This is the only component in the repository that holds a private key or talks
to a chain. It is a separate binary, run as a separate unix user, for one
reason: **the ingest-facing collector must not hold a funded key, and must not
depend on an RPC being reachable.** If the chain is down for a week, ingest is
unaffected; roots accumulate and anchor later.

## What it proves, and what it does not

Anchoring closes exactly one hole: today the collector itself is trusted.
Whoever operates it can rewrite `events/*.ndjson` after the fact and re-run
`verify` with a K0 they also hold. A root on a public chain pins what the store
contained at a given time, to anyone, forever, without trusting the operator and
without revealing K0 or any log content.

It does **not**:

- prove a record is authentic — that is the HMAC under the escrowed K0;
- stop the collector omitting a record before it is batched — sequence-gap
  detection catches that, the Merkle layer does not;
- prove when an event happened — only when the commitment was published. The
  upper bound is the block timestamp; the lower bound is nothing.

Every proof bundle repeats these three verbatim in its `not_claims`. Do not
paraphrase them in an incident report.

## What goes on chain

A 0-value transaction from the anchor account **to itself**, carrying:

```
calldata = "EDRMR1" (6 ASCII bytes) || root (32 bytes) || root_id (u64 big-endian)
```

46 bytes. No contract, no ABI, no deployment, no upgrade story, no contract
risk. Calldata is permanently retrievable through `eth_getTransactionByHash` on
any archive node and costs 16 gas per non-zero byte.

**Nothing but the root goes on chain.** No host names, no counts, no record
content, no K0. A root is 32 bytes of hash and reveals nothing; a host name
would publish your fleet inventory, permanently.

A contract (`event Root(uint64 indexed rootId, bytes32 root, uint64 timestamp)`)
is sketched in `server.md` §2.8 and is **not implemented here**. It is worth
deploying only if roots must be queryable on-chain by index, which is open
decision 3 for the operator. Calldata is the default and needs no decision.

## Running it

```bash
# The address to fund. No network, no transaction.
edr-anchor --key-file /etc/edr-anchor/key address

# One pass -- what a systemd timer wants.
edr-anchor --data-dir /var/lib/edr-collector \
           --rpc-url https://sepolia.base.org --chain-id 84532 \
           --key-file /etc/edr-anchor/key \
           run --once --confirmations 20

# Or stay resident.
edr-anchor ... run --interval-secs 60 --confirmations 20

# What is anchored and what is not. Local files only, no RPC.
edr-anchor --data-dir /var/lib/edr-collector status
```

`--chain-id` is checked against the node before anything is signed. Signing for
the wrong chain is how a testnet key ends up broadcasting on mainnet.

### Cost

One transaction per root. At the collector's `--root-interval-secs 600` that is
144 transactions a day, each about 21.7k gas. On an L2 that is a fraction of a
cent apiece — order of a few dollars a year. **Check current gas prices before
quoting a number to anyone**; these figures move. The knob is
`--root-interval-secs` on the collector, and the trade is linear: 3600s is 24
transactions a day with up to a one-hour worst-case proof latency.

## Crash safety

The failure this is designed against: the worker broadcasts, dies before
recording the transaction hash, restarts, and anchors the same root again from a
different nonce — burning gas and producing two conflicting anchors.

1. On start, scan `anchors.ndjson`. Any `submitted` with no matching `confirmed`
   is **in flight** and is resolved before any new work is considered.
2. A transaction the chain does not know is resubmitted **at the same nonce**,
   never a fresh one. Same nonce means at most one of the two can ever land.
3. Only then is an unanchored root picked up, oldest first, one at a time.
4. The `submitted` line is written and `fsync`ed **before**
   `eth_sendRawTransaction`. In the other order a crash in between loses the
   hash.
5. A previously confirmed transaction that stops resolving was reorged out: a
   `reorged` line is appended and the root is re-anchored. Nothing is ever
   rewritten in place.

`protocol_tests` in `src/main.rs` drives all five against `src/mock.rs`, a
JSON-RPC node that can be made to drop a transaction or lose a block on demand.
None of that is arrangeable on a public testnet, which is why the mock exists.

## Key handling

- The key comes from `--key-file` (mode `0600`, not a symlink, opened
  `O_NOFOLLOW`) or from `$EDR_ANCHOR_KEY`. **Never** from a command-line
  argument: `/proc/*/cmdline` is world-readable, and a key that reaches a
  process list has to be considered spent.
- The account needs gas and nothing else. Fund it with a small float. It signs
  0-value self-transfers; anything else it holds is at risk for no benefit.
- `--min-balance-wei` logs `CRITICAL` below the threshold and the balance is
  surfaced at `/api/merkle/status` and on the dashboard, because a silently
  unfunded worker looks exactly like a working one.

## Deployment: why the separate user matters

This process must not be able to read `hosts/*.enroll.json`. Those files hold
K0, and the entire forward-secrecy argument collapses if a key that also touches
the internet can read them. The isolation is enforced by unix permissions, not
by this binary's good behaviour — though it also does not link `edr-record` at
all, so there is no code path here that could parse an enrollment even if it
could open one.

```ini
# /etc/systemd/system/edr-anchor.service
[Unit]
Description=EDR Merkle root anchoring worker
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=edr-anchor
Group=edr-anchor
Environment=EDR_ANCHOR_RPC=https://sepolia.base.org
ExecStart=/usr/local/bin/edr-anchor \
    --data-dir /var/lib/edr-collector \
    --chain-id 84532 \
    --key-file /etc/edr-anchor/key \
    run --once --confirmations 20

# It reads one file and appends to two. Nothing else in the data directory is
# reachable, hosts/ least of all.
ReadOnlyPaths=/var/lib/edr-collector/roots.ndjson
ReadWritePaths=/var/lib/edr-collector/anchors.ndjson /var/lib/edr-collector/anchor-status.json
InaccessiblePaths=/var/lib/edr-collector/hosts /var/lib/edr-collector/events

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/edr-anchor.timer
[Unit]
Description=Anchor sealed EDR Merkle roots

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=15s

[Install]
WantedBy=timers.target
```

Set up once, as root:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin edr-anchor
install -d -o edr-anchor -g edr-anchor -m 0700 /etc/edr-anchor
install -o edr-anchor -g edr-anchor -m 0600 /dev/null /etc/edr-anchor/key
# paste the 64 hex characters into it, then:
chmod 0600 /etc/edr-anchor/key

# The two files this user touches, and nothing else under the data directory.
install -o edr-collector -g edr-anchor -m 0640 /dev/null /var/lib/edr-collector/roots.ndjson
install -o edr-anchor   -g edr-anchor -m 0640 /dev/null /var/lib/edr-collector/anchors.ndjson
chmod 0700 /var/lib/edr-collector/hosts     # K0 lives here. Collector only.
```

## Verifying an anchor, as a third party

Nothing above is needed. Given a proof bundle from the collector's retrieval
API:

```bash
verify.py --proof proof.json --rpc-url https://sepolia.base.org
```

That recomputes the record's leaf, replays both audit paths, fetches the
anchoring transaction from a public endpoint, and compares bytes 6..38 of its
calldata against the root. It uses no K0, no access to the collector, and
nothing outside the Python standard library.
