# WATCHTOWER — API Reference

Internal Python API reference for everything built so far. This documents
the public interface of each package — the classes/functions listed under
each package's `__init__.py` `__all__`. Not an HTTP API reference (that's
`portal/api/*` once built — this file gets a companion section then).

---

## nucleus/

Foundation types. No side effects except `nucleus.config`'s module-level
`cfg` singleton, which reads `config.ini` at first import.

```python
from nucleus.record     import LogRecord, DeviceRecord, AlertRecord
from nucleus.constants  import LogFormat, LogCategory, DeviceType, DeviceStatus, AlertLevel, Role
from nucleus.config     import cfg
from nucleus.exceptions import WatchtowerError, ...  # full hierarchy in nucleus/exceptions.py
from nucleus.telemetry  import metrics
```

- `LogRecord.from_raw(raw, sender_ip, sender_port=0, transport="udp")` — construct from a raw string
- `LogRecord.seal()` — compute and store `integrity_hash`; call as the last pipeline step
- `LogRecord.verify_integrity()` — recompute hash, compare to stored
- `metrics.snapshot()` — full point-in-time dict of every counter/gauge across every layer

---

## ledger/

The only layer that touches SQLite. `Vault` → `Scribe` (writes) / `Archivist`
(reads), always in that pairing.

```python
from ledger.vault     import Vault
from ledger.scribe    import Scribe
from ledger.archivist import Archivist, LogFilter
from ledger.indexer   import Indexer
from ledger.retention import RetentionManager
```

**Vault**
- `vault.initialise()` — run migrations, verify connectivity. Call once at startup.
- `with vault.connection() as conn:` — auto commit/rollback
- `with vault.transaction() as conn:` — explicit batch transaction
- `vault.stats()` — size, page count, per-table row counts

**Scribe** (writes)
- `write(record: LogRecord) -> int` / `write_batch(records) -> int`
- `upsert_device(device: DeviceRecord)` / `update_device_ping(ip, reachable, rtt_ms)` / `update_device_status(ip, status)`
- `write_alert(alert: AlertRecord) -> int` / `acknowledge_alert(alert_id, ack_by)` / `resolve_alert(alert_id, notes="")`
- `create_alert_rule(...) -> int` / `update_alert_rule(...)` / `set_rule_enabled(rule_id, enabled)` / `delete_alert_rule(rule_id)`
- `write_audit(actor, action, target, detail="", ...)`
- `write_failover_event(event_type, from_server="", to_server="", virtual_ip="", duration_sec=None, detail="")`
- `write_intake_snapshot()`

**Archivist** (reads)
- `fetch_devices()` / `fetch_device(ip)`
- `fetch_device_logs(ip, ...)` (see `LogFilter`)
- `fetch_alerts(acknowledged=None, resolved=None, level=None, limit=50)`
- `fetch_alert_rules(enabled_only=False)` / `fetch_alert_rule(rule_id=None, name=None)`
- `fetch_audit_trail(actor=None, limit=100)`
- `fetch_failover_log(limit=100, event_type=None)` / `last_failover_event()`
- `stats_summary(hours=24)` / `stats_category_totals()`

---

## beacon/

Network awareness. Never touches SQLite directly — reads via `Archivist`, writes via `Scribe`.

```python
from beacon.cartographer import Cartographer, ClassificationEvidence
from beacon.arp_scout    import ARPScout, ARPEntry
from beacon.snmp_probe   import SNMPProbe, InterfaceStats
from beacon.sonar        import Sonar, PingResult
from beacon.herald       import Herald
from beacon.topology     import TopologyMapper, NeighborEdge
```

- `Cartographer().classify(ClassificationEvidence(...)) -> DeviceType str` — MAC OUI > SNMP sysDescr > hostname pattern > syslog format, in that order
- `ARPScout(subnet_filter="").scan() -> list[ARPEntry]` — reads kernel ARP table, no active probing
- `SNMPProbe(community="public").get_sysdescr(ip)` / `.get_interfaces(ip) -> list[InterfaceStats]` — shells to `snmpget`/`snmpwalk`
- `Sonar(scribe, archivist).sweep() -> dict` — concurrent ICMP ping across every known device, writes `ping_status`
- `Herald(scribe, archivist).register_from_log(record)` — call **per LogRecord**, cheap, writes device registry
- `Herald(...).sweep_log_status() -> dict` — call on a schedule, demotes online→silent→offline off log recency, writes `status`
- `TopologyMapper(probe).build_graph(known_devices) -> {"nodes": [...], "edges": [...]}`

---

## chronicle/

Audit and compliance. Also never touches SQLite directly.

```python
from chronicle.auditor    import Auditor
from chronicle.trail      import Trail, TrailFilter
from chronicle.compliance import ComplianceGenerator, ComplianceReport, ComplianceError
```

- `Auditor(scribe).login_success/login_failed/config_change/permission_denied/...(...)` — named methods over free-text action strings
- `Trail(archivist).query(TrailFilter(actor=, action=, result=, keyword=, from_time=, to_time=, limit=, offset=)) -> list[dict]`
- `Trail(...).recent_failures(hours=24)` / `.actor_activity(actor, days=30)` / `.action_breakdown(hours=24)`
- `ComplianceGenerator(archivist, trail).generate(period_days=30) -> ComplianceReport`
- `ComplianceGenerator(...).to_csv(report)` / `.to_json(report)` / `.to_pdf(report, path)` — PDF needs `fpdf2` installed

---

## relay/

High availability. Only `failover_log.py` touches the ledger.

```python
from relay.heartbeat   import Heartbeat, RelayRole, RoleTransition
from relay.consensus   import ConsensusChecker, ConsensusState
from relay.replicator  import Replicator, ReplicationStatus
from relay.failover_log import FailoverLog
```

- `Heartbeat(virtual_ip, on_transition=callback)` — role determined by whether `virtual_ip` is bound locally (`ip addr show`), not by trusting Keepalived's state file
- `heartbeat.role` / `heartbeat.is_primary()` / `heartbeat.on_notify(state)` — feed Keepalived notify-script output in
- `ConsensusChecker(peer_ip, required_consecutive_failures=3).record_check(peer_reachable)` / `.should_promote()` / `.verify_not_isolated(gateway_ip)`
- `Replicator(db_path).is_installed()` / `.status() -> ReplicationStatus` / `.restore(...)` — wraps the `litestream` binary
- `FailoverLog(scribe, archivist, this_server=).record_promotion(...)` / `.record_transition(...)` / `.recent(limit=10)`

**Required config.ini keys used:** `[relay] peer_ip`, `virtual_ip`, `gateway_ip`, `heartbeat_interval`, `sync_interval`, `role`.

---

## dispatch/

Alerting. Only `rulebook.py` (rule CRUD) and `incident.py` (alert writes/reads) touch the ledger.

```python
from dispatch.rulebook    import RuleBook, AlertRule, AlertCondition, AlertAction
from dispatch.correlator  import Correlator, MatchEvent
from dispatch.incident    import IncidentManager
from dispatch.notifier    import Notifier, NotifierRegistry
from dispatch.notifier.browser     import BrowserNotifier
from dispatch.notifier.email_relay import EmailNotifier
from dispatch.notifier.webhook     import WebhookNotifier
from dispatch.notifier.telegram    import TelegramNotifier
```

**Rule condition schema** (`condition_json`):
```json
{"field": "severity", "op": "in", "value": ["CRIT","ALERT","EMERG"],
 "window_sec": 60, "count": 1, "group_by": null}
```
`op` ∈ `eq | ne | in | not_in | contains | gte | lte`. `group_by` is optional —
set it to track counts per distinct value of a field (e.g. per `username`).

**Rule action schema** (`action_json`):
```json
{"notify": ["email", "telegram", "browser"], "cooldown_sec": 300}
```

- `RuleBook(scribe, archivist).seed_builtins()` — inserts 3 default rules once, no-op after
- `RuleBook(...).load_active() -> list[AlertRule]` — parses + validates every enabled rule
- `Correlator(rulebook).evaluate(record) -> list[MatchEvent]` — call per LogRecord
- `Correlator(...).reload_rules()` — call after any rule CRUD so correlator picks it up without a restart
- `IncidentManager(scribe, archivist, notifiers).open_from_match(match) -> alert_id`
- `IncidentManager(...).acknowledge(alert_id, actor)` / `.resolve(alert_id, notes="")`
- `IncidentManager(...).open_incidents(level=None, limit=100)` — `resolved=False` view, the dashboard's main list
- `NotifierRegistry().register(notifier)` / `.dispatch(channels, alert, rule) -> {channel: bool}` — never raises, per-channel result dict

**Required config.ini keys used:** `[notifications]` section — `email_enabled`, `smtp_host/port/user/password`,
`alert_recipients`, `telegram_enabled`, `telegram_token/chat_id`, `webhook_enabled`, `webhook_url`.

---

## Exception hierarchy quick reference

All inherit `WatchtowerError` (in `nucleus/exceptions.py`). Catch the
specific subclass, never bare `Exception`, per the codebase convention:

```
WatchtowerError
├── ConfigError (ConfigKeyMissing, ConfigValueInvalid)
├── IntakeError (SocketBindError, RateLimitExceeded, ConduitFullError)
├── PipelineError (ParseError, ValidationError, ...)
├── LedgerError (DatabaseConnectionError, WriteError, ReadError, MigrationError, IntegrityError)
├── BeaconError (PingError, SNMPError, ARPScanError)
├── AuthError (InvalidCredentials, AccountLockedOut, SessionExpired, PermissionDenied, ...)
├── DispatchError (RuleLoadError, NotificationError)
├── RelayError (ReplicationError, SplitBrainError)
└── SchedulerError (JobExecutionError)
```
