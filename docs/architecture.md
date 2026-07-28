# WATCHTOWER — Architecture

Last updated: reflects state as of the beacon/chronicle/relay/dispatch build session.
Keep this current as layers are added — don't let it drift from the code.

## Layer map

```
nucleus/     foundation — types, config, constants, exceptions, telemetry
ledger/      persistence — SQLite (WAL mode), the ONLY layer that touches SQL directly
beacon/      network awareness — device discovery, classification, reachability
chronicle/   audit and compliance — who did what, when
relay/       high availability — VRRP failover, split-brain prevention, Litestream
dispatch/    alerting — rule matching, incident lifecycle, notifications

intake/      NOT YET BUILT — UDP/TCP listener, rate limiting
pipeline/    NOT YET BUILT — parsing (forge/*), validation, sealing
sentinel_gate/ NOT YET BUILT — auth, sessions, RBAC, API keys
portal/      NOT YET BUILT — Flask web UI
scheduler/   NOT YET BUILT — background job runner
```

## The one hard rule: ledger owns all SQL

No other layer opens a SQLite connection or writes raw SQL. Every read goes
through `ledger.archivist.Archivist`, every write through `ledger.scribe.Scribe`.
This was violated nowhere in beacon/chronicle/relay/dispatch — where a new
capability needed a DB operation that didn't exist yet (failover log,
alert rule CRUD, `resolved` filtering), the method was added to `scribe.py`/
`archivist.py` rather than bypassed. See CHANGELOG.md for the exact methods
added and when.

Why this matters in practice: `Vault` manages one SQLite connection per
thread (WAL mode, tuned pragmas). If a second layer opened its own
connection, you'd get two independent pragma configurations and a second
source of "what's the current schema version" — exactly the kind of bug
that's invisible until concurrent writes start colliding.

## Data flow (target — some links not wired yet)

```
device ──syslog──> intake/listener.py ──> conduit queue
                                              │
                                              v
                                       pipeline/sieve.py (detect format)
                                              │
                                              v
                                       pipeline/forge/*.py (parse)
                                              │
                                              v
                                       pipeline/marshal.py (normalize -> LogRecord)
                                              │
                                              v
                                       pipeline/sentinel.py (validate, hash, seal)
                                              │
                        ┌─────────────────────┼─────────────────────┐
                        v                     v                     v
                 ledger/scribe.py     beacon/herald.py      dispatch/correlator.py
                 .write(record)       .register_from_log()  .evaluate(record)
                        │                     │                     │
                        v                     v                     v
                 SQLite (auth_logs,     devices table          MatchEvent, if any
                 network_logs, etc.)                                │
                                                                     v
                                                          dispatch/incident.py
                                                          .open_from_match()
                                                                     │
                                                          ┌──────────┴──────────┐
                                                          v                     v
                                                   alert_history table   notifier/* (fan-out)
```

Every arrow out of `pipeline/sentinel.py` is independent — `herald.register_from_log()`
and `correlator.evaluate()` should both be called per-record from the same
call site (likely `core.py`'s ingest loop or `pipeline/marshal.py`'s output
hook), but neither depends on the other succeeding.

## Two independent device status axes (beacon/)

The `devices` table tracks two things that are easy to conflate but aren't
the same:

| Column        | Owned by            | Driven by                          |
|---------------|----------------------|-------------------------------------|
| `status`      | `beacon/herald.py`   | time since last **log message**     |
| `ping_status` | `beacon/sonar.py`    | ICMP reachability, independent of logs |

A device can be reachable but quiet (fine — maybe just idle) or unreachable
but recently logged (interesting — it just went down). Keep them separate;
don't collapse them into one "online/offline" field.

## Relay: VIP presence is ground truth, not the state file

`relay/heartbeat.py` determines VRRP role by checking whether the virtual
IP is actually bound to a local interface (`ip -4 addr show`), not by
trusting Keepalived's own notify-script state file. The state file is read
only as a secondary signal (to distinguish `standby` from `fault`). This
means heartbeat.py stays correct even if Keepalived crashes mid-transition
and leaves a stale state file behind — the kernel doesn't lie about which
interface has the address.

`relay/consensus.py` requires **3 consecutive** peer-unreachable checks
before considering promotion (avoids flapping on one dropped packet), and
separately checks this node's own gateway is reachable before trusting a
"peer is down" read — a standby that's lost its own uplink will *also* see
the peer as unreachable, and promoting in that state is exactly how you get
split-brain.

## Dispatch: rules are data, not code

Alert rules live in the `alert_rules` table as `condition_json`/`action_json`,
not as Python `if` statements scattered through the pipeline. `dispatch/
correlator.py` evaluates every active rule against every `LogRecord` using
one generic sliding-window matcher — adding a new detection means inserting
a row (via `dispatch/rulebook.py`), not shipping code. See
`api_reference.md` for the exact condition/action schema.

Correlation state (the sliding windows themselves) lives in process memory,
not the database — a restart loses at most a few minutes of in-progress
window state, which is the correct tradeoff (better to briefly under-fire
after a restart than replay a stale window from disk).

## Config requirements

`nucleus/config.py`'s `WatchtowerConfig` reads `config.ini` from the project
root and validates on load — missing required keys raise `ConfigError`/
`ConfigKeyMissing` immediately at import time, not later at first use.
See `deployment.md` for the full list of required and optional keys per
section (`[server]`, `[intake]`, `[ledger]`, `[auth]`, `[relay]`,
`[scheduler]`, `[notifications]`, `[beacon]`).

## What's tested vs. what's assumed

Everything in `beacon/`, `chronicle/`, `relay/`, `dispatch/` was
functionally smoke-tested against a real temporary SQLite DB during
development — device registration, status sweeps, audit writes/queries,
failover event logging, and the full rule-match → incident → notification
path, including sliding-window threshold behavior and cooldown gating.

Not tested (no real hardware/network available to test against):
- `beacon/snmp_probe.py` and `beacon/topology.py` against a real switch's
  SNMP agent — the command-building and parsing logic is correct per the
  MIB spec, but LLDP-MIB population varies by vendor in practice.
- `relay/heartbeat.py` and `relay/consensus.py` against a real two-node
  Keepalived pair — the VIP-presence logic is straightforward but the
  actual failover timing/behavior needs a real second box.
- `relay/replicator.py` against a real Litestream deployment.

Test these against real devices before trusting them in production, same
as you'd do for anything network-facing.
