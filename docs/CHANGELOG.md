# WATCHTOWER — Changelog

Format: newest first. Log entries as you build, not retroactively — this
file's whole purpose is to not need reconstructing later from memory.

## 2026-07-26 — beacon, chronicle, relay, dispatch

Added four full layers plus targeted extensions to `ledger/` and `nucleus/`
to support them. Every method below was functionally tested against a real
temporary SQLite database, not just import-checked.

### Added: `beacon/`
- `cartographer.py` — device classification from MAC OUI / SNMP sysDescr / hostname / syslog format
- `arp_scout.py` — kernel ARP table reader (`ip neighbor show`, `/proc/net/arp` fallback)
- `snmp_probe.py` — SNMP GET/WALK via net-snmp CLI tools (no pysnmp dependency)
- `sonar.py` — concurrent ICMP ping sweep, writes `devices.ping_status`
- `herald.py` — per-message device registration (`register_from_log`) + log-activity status sweep, writes `devices.status`
- `topology.py` — LLDP-MIB neighbor discovery, builds node/edge graph for `portal/static/topology.js` (once built)

### Added: `chronicle/`
- `auditor.py` — named audit-writing methods (login, config_change, permission_denied, etc.) over `Scribe.write_audit`
- `trail.py` — filtered/paginated audit trail queries over `Archivist.fetch_audit_trail`
- `compliance.py` — `ComplianceReport` generation, CSV/JSON export always available, PDF via optional `fpdf2`

### Added: `relay/`
- `heartbeat.py` — VRRP role determined by VIP presence (`ip addr show`), not by trusting Keepalived's notify-script state file alone
- `consensus.py` — split-brain prevention: 3 consecutive peer-unreachable checks + self-isolation (gateway reachability) check before promotion
- `replicator.py` — wraps the `litestream` binary for replication status/restore
- `failover_log.py` — the only file in `relay/` that touches the ledger

### Added: `dispatch/`
- `rulebook.py` — `AlertRule`/`AlertCondition`/`AlertAction` schema, CRUD, 3 builtin rule seeds (critical-severity, repeated-failed-logins, firewall-scan-detect)
- `correlator.py` — in-memory sliding-window rule matcher (deque per rule+group_key), cooldown gating
- `incident.py` — open → acknowledged → resolved lifecycle, notification fan-out after the DB write (never before)
- `notifier/` — `browser.py` (in-memory SSE bridge), `email_relay.py` (SMTP), `webhook.py` (JSON POST), `telegram.py` (Bot API) — all behind one `Notifier` interface

### Modified: `ledger/scribe.py`
- Added `resolve_alert(alert_id, notes="")`
- Added `create_alert_rule`, `update_alert_rule`, `set_rule_enabled`, `delete_alert_rule` (refuses to delete `builtin` rules)
- Added `write_failover_event(event_type, from_server="", to_server="", virtual_ip="", duration_sec=None, detail="")`

### Modified: `ledger/archivist.py`
- Extended `fetch_alerts` with a `resolved` filter (previously only `acknowledged`/`level`)
- Added `fetch_alert_rule(rule_id=None, name=None)` — single-rule lookup, `fetch_alert_rules` already existed
- Added `fetch_failover_log(limit=100, event_type=None)` and `last_failover_event()`

### Modified: `nucleus/telemetry.py`
- Added `relay_*` metrics namespace (`relay_role`, `relay_failovers_total`, `relay_split_brain_events`,
  `relay_peer_unreachable`, `relay_replication_lag_sec`, `relay_replication_errors`), matching the
  existing per-layer convention (`intake_*`, `pipeline_*`, `ledger_*`, `beacon_*`, `dispatch_*`, `portal_*`)

### Modified: `nucleus/config.py`
- Added `cfg.relay.gateway_ip` — needed by `relay/consensus.py`'s self-isolation check, wasn't in `_RelayConfig` yet

### Known gaps from this session
- `intake/`, `pipeline/`, `portal/`, `scheduler/`, `sentinel_gate/`, and `core.py` still don't exist —
  everything above is a tested library, not yet a running server. See `deployment.md` §5 for build order.
- `beacon/snmp_probe.py`, `beacon/topology.py`, and `relay/heartbeat.py`/`consensus.py` are untested
  against real hardware (no SNMP-capable device or second HA node available during development) —
  logic is correct per spec, but confirm against real devices before production use.

---

## Baseline (prior to this session)

`nucleus/`, `ledger/`, `pipeline/`, and `sentinel_gate/` core modules built and verified across earlier
sessions. Key decisions from that work (see `architecture.md` for the full rationale):

- SQLite with WAL mode, FTS5 full-text search, PBKDF2-HMAC-SHA256 auth
- Four-role RBAC (`admin`/`analyst`/`viewer`/`auditor`), 13 permissions
- DHCP Option 7 agentless collection strategy
- Dual-server HA design: VRRP/Keepalived + Litestream (implemented this session in `relay/`)
- Custom thematic naming convention across the whole tree (`intake`, `ledger`, `sentinel_gate`, `beacon`, etc.)

Exact per-file dates from that earlier work weren't tracked in this file — starting the discipline now.
