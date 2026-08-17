# Installing the agent

Every step below exists because of a finding in `THREAT_MODEL.txt`. The IDs in
brackets point at the entry that explains why.

## 1. Binary and permissions

The binary is executed by a root service, so anything that can write to it — or
to any directory on the path to it — owns the host. [AGT-6]

```sh
install -o root -g root -m 0755 target/release/edr-agent /usr/local/bin/edr-agent
install -o root -g root -m 0644 packaging/edr-agent.service /etc/systemd/system/
```

Check the whole path, not just the file:

```sh
namei -l /usr/local/bin/edr-agent
```

No component may be group- or world-writable.

## 2. Do not use `setcap` without restricting execute

`setcap cap_bpf,cap_perfmon+ep` is the usual advice for avoiding a root service,
and on its own it makes things worse: every user who can execute the binary now
invokes it *with those capabilities*. [AGT-7]

If you grant capabilities, restrict execution in the same breath:

```sh
chgrp edr /usr/local/bin/edr-agent
chmod 0750 /usr/local/bin/edr-agent
setcap cap_bpf,cap_perfmon+ep /usr/local/bin/edr-agent
```

A capability grant without a matching execute restriction is a net loss.

## 3. First start — record K0

The agent generates a root sealing key on first start and prints it once:

```
FIRST START: root sealing key (K0) for this agent.

    a3f1...  (64 hex characters)
```

**Copy this off the machine before doing anything else.** [NOW-4, Section 8]

The key on disk evolves forward every 60 seconds and old generations are
destroyed, which is what makes records written before a compromise unforgeable
to an attacker who later gets root. That property is worth nothing if the only
copy of K0 lives on the host being attacked.

If both `/var/log/edr/edr.wal` and `/var/log/edr/edr.state` are deleted, the
agent starts fresh with a *new* K0. The resulting chain is internally
consistent and will verify against itself — and will fail against the K0 you
escrowed. That failure is the detection. [NOW-8]

## 4. Verifying

```sh
python3 verify.py --key <K0-hex> /var/log/edr/edr.wal
```

After a rotation the chain spans two files. Pass them in order:

```sh
python3 verify.py --key <K0-hex> /var/log/edr/edr.wal.1 /var/log/edr/edr.wal
```

Only one archive generation is kept. Ship or archive `edr.wal.1` before the
next rotation overwrites it. [NOW-14]

## 5. The collector

Everything the agent structurally cannot do for itself happens here, because
this runs somewhere the monitored host's root does not control.

### Install it (on the collector machine, not the monitored host)

```sh
useradd --system --home /var/lib/edr-collector --shell /usr/sbin/nologin edr-collector
install -d -o edr-collector -g edr-collector -m 0700 /var/lib/edr-collector
install -o root -g root -m 0755 target/release/edr-collector /usr/local/bin/
install -o root -g root -m 0644 packaging/edr-collector.service /etc/systemd/system/
systemctl enable --now edr-collector
```

It binds to `127.0.0.1:8080` and speaks plain HTTP. Put TLS in front of it.

### Enroll each host

K0 is entered here **by you, out of band**. The agent never transmits it: if it
did, a TLS-terminating proxy would see the key and the entire forward-secrecy
argument would collapse. [PRX-1]

```sh
edr-collector enroll \
  --host web-01.prod \
  --key <the K0 the agent printed on first start> \
  --build-id "$(stat -c '%d:%i:%Y' /usr/local/bin/edr-agent)"
```

`--build-id` is what catches a binary swapped for a heartbeating stub. [SUP-2]

Re-enrolling an existing host is refused without `--force`, because a silent
re-key is exactly what a wiped-and-restarted agent looks like. [NOW-8]

### Point the agent at it

```sh
edr-agent --collector-url https://collector.example.net --host-id web-01.prod
```

Without `--collector-url` the agent runs local-only: records are still sealed
and written, but nothing leaves the host.

### Check on it

```sh
edr-collector status                      # per-host seq, breaks, last seen
edr-collector verify --host web-01.prod   # re-verify the store from K0
```

`verify` re-derives every key from K0 and re-checks every MAC. The ingest path
already verified each record on arrival, so this answers the question that
matters afterwards: has the **collector's own store** been altered since.

### What the collector buys you

| Without it | With it |
|---|---|
| Deleting the newest records leaves a chain that verifies perfectly | The gap in `seq` is visible immediately [NOW-3, STO-4] |
| Wiping WAL + state mints a new K0 and a clean history | Records fail against the enrolled K0 [NOW-8] |
| Timestamps come from a host whose clock root controls | Receipt time is stamped here [NOW-7] |
| A stopped agent looks like a quiet host | `--silence-secs` alerts on it [PRX-5] |
| A replaced binary reports "all healthy" | Build id mismatch is recorded [SUP-2] |
| Retention is whatever fits in 256 MB | Acked records are trimmed from the host |

### The dashboard

`serve` also brings up a read-only web console on a **second** port:

```sh
edr-collector serve --listen 127.0.0.1:8080 --dashboard-listen 127.0.0.1:8081
```

Open `http://127.0.0.1:8081/`. It shows the fleet at a glance (hosts, silent
hosts, chain breaks, build mismatches), a live alert feed with per-host and
per-severity filters, and a detail view for any event including its MAC and the
MAC it chains to. It polls every 5 seconds and reads the same event store that
`verify` reads — there is no second database to fall out of step.

Two ports on purpose, and they are not interchangeable:

| Port | Direction | Auth | Who reaches it |
|---|---|---|---|
| `--listen` 8080 | write-only ingest | every record MAC-verified | the proxy (untrusted) |
| `--dashboard-listen` 8081 | read-only | **none** | analysts only |

**The dashboard has no authentication of its own.** Anyone who can open the port
reads every alert on every host. Serving it from the ingest socket would hand
the fleet's telemetry to the one component the threat model already treats as
hostile, which is why it is a separate listener rather than another route.

Put it behind something that authenticates — SSO proxy, mTLS, VPN-only
interface — or just tunnel to it and skip exposing it at all:

```sh
ssh -N -L 8081:127.0.0.1:8081 collector-host
```

Pass `--dashboard-listen off` to disable it.

A note on why the page is written the way it is: `process_name` and `filename`
are chosen by whoever executed the binary, so an attacker can name a file
`<img src=x onerror=...>` and get that string into an analyst's browser. The
page therefore renders every field with `textContent` and never `innerHTML`,
and is served with a CSP that blocks outbound connections, so an injection that
does land still cannot exfiltrate. Keep both properties if you modify it.

### Tuning the shipper

`--ship-batch` (default 500) and `--ship-interval` (default 5s) together set the
catch-up ceiling: 100 records/second by default. This is deliberate. After a
six-hour outage the WAL holds a large backlog, and an unthrottled drain would
saturate the uplink and spike CPU at exactly the moment someone is already
looking at the host. Raise it if your uplink can take it.

## 6. What this install does not give you

- **No TLS of its own.** The collector speaks plain HTTP and expects a
  terminating proxy in front of it. If you skip that, batches cross the network
  in the clear: they still cannot be forged, but anyone on the path can read
  every process execution on every monitored host. [NET-1]
- **The collector is now the crown jewels.** It holds every host's K0. Someone
  who reads `/var/lib/edr-collector/hosts/` can forge any host's entire history
  retroactively, which is strictly more power than compromising any single
  agent. Back it up, restrict it, and watch it more closely than the hosts.
- **No dashboard.** `status` and `verify` are CLI only. Silence and chain-break
  alerts go to stderr, which means the journal. Nothing pages anyone.
- **The agent still runs as root.** The systemd hardening bounds the damage; it
  does not remove the condition. [AGT-2]
- **Only `sched_process_exec` is hooked.** Anything that never calls execve is
  invisible: code injected into a running process, an interpreter loading a
  payload from a socket, a library loaded via LD_PRELOAD into a process that
  already started. [SEN-2]
- **No CO-RE.** The vmlinux bindings are generated against one kernel. On a
  different kernel the struct offsets can be wrong, and wrong offsets produce
  confident nonsense rather than an error. Regenerate per target kernel. [SEN-7]
