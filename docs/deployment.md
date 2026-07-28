# WATCHTOWER — Deployment Notes

Honest status check first: `intake/`, `pipeline/`, `portal/`, `scheduler/`,
and `core.py` don't exist yet. Everything below makes `nucleus/`, `ledger/`,
`beacon/`, `chronicle/`, `relay/`, `dispatch/` importable and testable as
a library — it is not yet a running syslog server. This doc covers what's
needed to get that far, and flags exactly what's still missing to go live.

## 1. Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
```

Everything built so far (`ledger/`, `beacon/`, `chronicle/`, `relay/`,
`dispatch/`) uses **stdlib only** — `sqlite3`, `smtplib`, `urllib`,
`subprocess`, `threading`, `concurrent.futures`, `dataclasses`. No
`requirements.txt` entries needed for these layers as they stand.

One optional dependency:
```bash
pip install fpdf2 --break-system-packages   # only needed for chronicle/compliance.py's to_pdf()
```
CSV and JSON compliance export work without it.

## 2. OS-level dependencies

| Tool | Needed by | Install |
|---|---|---|
| `ip` (iproute2) | `beacon/arp_scout.py`, `relay/heartbeat.py` | Preinstalled on virtually every modern Linux |
| `ping` | `beacon/sonar.py` | Preinstalled |
| `snmpget`/`snmpwalk` (net-snmp) | `beacon/snmp_probe.py`, `beacon/topology.py` | `apt install snmp` (Debian/Ubuntu) or `yum install net-snmp-utils` (RHEL/CentOS) |
| `litestream` | `relay/replicator.py` | `curl -LO https://github.com/benbjohnson/litestream/releases/...` — see litestream.io/install |
| `keepalived` | `relay/heartbeat.py`'s notify-script integration | `apt install keepalived` |

Everything degrades cleanly if a tool is missing — `SNMPError`/`ARPScanError`/
`ReplicationError` are raised with an install hint rather than crashing
uncaught. Confirmed by test during development.

## 3. config.ini

`nucleus/config.py` requires this at the project root and validates on
load — missing required keys raise `ConfigError` immediately at import,
not later at first use. Required keys are marked below; everything else
has a sane default in `nucleus/config.py` if omitted.

```ini
[server]
name = WATCHTOWER
environment = production          ; required
debug = false
log_level = INFO

[intake]
udp_host = 0.0.0.0                ; required
udp_port = 514                    ; required
tcp_port = 514                    ; required
tls_port = 6514
tls_enabled = false
queue_size = 10000
rate_limit = 1000

[ledger]
db_path = logs/syslog.db          ; required
retention_auth_days = 90
retention_network_days = 60
retention_firewall_days = 90
retention_system_days = 30
retention_app_days = 30
fts_enabled = true
wal_mode = true

[auth]
admin_password_hash =             ; required — see sentinel_gate/auth.py once built for hashing
secret_key =                      ; required — generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
session_lifetime = 28800
max_failed_logins = 5
lockout_duration = 300

[relay]
enabled = false
role = standalone                 ; standalone | primary | standby
peer_ip =
virtual_ip =
gateway_ip =                      ; used by relay/consensus.py's self-isolation check — set this
heartbeat_interval = 1
sync_interval = 5

[scheduler]
enabled = true
backup_hour = 2
retention_hour = 3
digest_hour = 7
snmp_poll_interval = 300

[notifications]
email_enabled = false
smtp_host =
smtp_port = 587
smtp_user =
smtp_password =
alert_recipients =                ; comma-separated
telegram_enabled = false
telegram_token =
telegram_chat_id =
webhook_enabled = false
webhook_url =

[beacon]
ping_interval = 30
ping_timeout = 2
offline_threshold = 900
silent_threshold = 300
arp_scan_enabled = false
snmp_enabled = false
snmp_community = public
subnet =
```

**Never commit `config.ini` with real `secret_key`/`admin_password_hash`/
`smtp_password`/`telegram_token` values to git.** Add it to `.gitignore`
now if it isn't already; keep a `config.ini.example` with blanks in the repo
instead.

## 4. What you can actually run today

A standalone Python session (or a test script) can exercise the full
built stack against a real SQLite file:

```python
from ledger.vault import Vault
from ledger.scribe import Scribe
from ledger.archivist import Archivist

vault = Vault("logs/syslog.db")
vault.initialise()              # runs migrations 001 + 002
scribe, archivist = Scribe(vault), Archivist(vault)

# beacon, chronicle, relay, dispatch all wire onto scribe/archivist
# exactly as shown in each package's __init__.py docstring
```

This will create and migrate a real database, and every method in
`beacon/`, `chronicle/`, `relay/`, `dispatch/` will work against it. What
won't happen automatically: nothing is listening on port 514, nothing is
parsing incoming syslog, and there's no web UI. That's `intake/`,
`pipeline/`, and `portal/` — build those next to go from "tested library"
to "running server."

## 5. Path to a live system, in order

1. **`intake/`** — UDP listener + conduit queue. Nothing arrives without this.
2. **`pipeline/`** — at minimum `sieve.py` + `forge/bsd.py` (RFC 3164 covers
   most switches' outer envelope) + `marshal.py` + `sentinel.py`. This is
   where `LogRecord`s get created — everything downstream depends on it.
3. **`core.py`** — wire `intake → pipeline → {ledger.write, beacon.herald.register_from_log,
   dispatch.correlator.evaluate}` into one ingest loop.
4. **`scheduler/`** — cron-equivalent for `herald.sweep_log_status()`,
   `sonar.sweep()`, `retention.run()`, `heartbeat.poll_for_transition()`,
   compliance report generation. Nothing above needs a live scheduler to be
   *testable*, but it needs one to run unattended.
5. **`sentinel_gate/`** — before `portal/` is exposed to anyone but you.
6. **`portal/`** — the dashboard. Last, deliberately — it's the piece most
   dependent on everything else already working.

## 6. Systemd unit (reference — not yet in `deploy/systemd/`)

Once `core.py` exists:

```ini
# /etc/systemd/system/watchtower.service
[Unit]
Description=WATCHTOWER Log Management Platform
After=network.target

[Service]
Type=simple
User=watchtower
WorkingDirectory=/opt/watchtower
ExecStart=/opt/watchtower/venv/bin/python core.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

This is illustrative, not tested — write the real one when `deploy/systemd/`
gets built, and confirm `User=watchtower` actually has permission on
`db_path` and the SNMP/ping binaries first.
