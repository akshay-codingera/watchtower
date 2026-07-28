-- =============================================================================
-- 001_initial.sql
-- WATCHTOWER — Initial Schema
-- =============================================================================
-- Creates the complete base schema for WATCHTOWER v1.
-- All tables, indexes, constraints, and triggers defined here.
-- This migration is idempotent — safe to detect if already applied.
-- =============================================================================

-- ── Per-category log tables ───────────────────────────────────────────────────
-- Each category gets its own table for partition-like performance.
-- All share identical column structure for the all_logs UNION view.

CREATE TABLE IF NOT EXISTS auth_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    facility        TEXT    NOT NULL DEFAULT 'user',
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    hostname        TEXT    NOT NULL DEFAULT '',
    sender_ip       TEXT    NOT NULL DEFAULT '',
    sender_port     INTEGER NOT NULL DEFAULT 0,
    app_name        TEXT    NOT NULL DEFAULT '',
    proc_id         TEXT    NOT NULL DEFAULT '',
    msg_id          TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    raw_message     TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'unknown',
    log_category    TEXT    NOT NULL DEFAULT 'auth',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    transport       TEXT    NOT NULL DEFAULT 'udp',
    source_ip       TEXT    NOT NULL DEFAULT '',
    dest_ip         TEXT    NOT NULL DEFAULT '',
    source_port     INTEGER NOT NULL DEFAULT 0,
    dest_port       INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    action          TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL DEFAULT '',
    geo_country     TEXT    NOT NULL DEFAULT '',
    geo_city        TEXT    NOT NULL DEFAULT '',
    geo_isp         TEXT    NOT NULL DEFAULT '',
    is_threat       INTEGER NOT NULL DEFAULT 0,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    rdns            TEXT    NOT NULL DEFAULT '',
    integrity_hash  TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS network_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    facility        TEXT    NOT NULL DEFAULT 'local0',
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    hostname        TEXT    NOT NULL DEFAULT '',
    sender_ip       TEXT    NOT NULL DEFAULT '',
    sender_port     INTEGER NOT NULL DEFAULT 0,
    app_name        TEXT    NOT NULL DEFAULT '',
    proc_id         TEXT    NOT NULL DEFAULT '',
    msg_id          TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    raw_message     TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'unknown',
    log_category    TEXT    NOT NULL DEFAULT 'network',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    transport       TEXT    NOT NULL DEFAULT 'udp',
    source_ip       TEXT    NOT NULL DEFAULT '',
    dest_ip         TEXT    NOT NULL DEFAULT '',
    source_port     INTEGER NOT NULL DEFAULT 0,
    dest_port       INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    action          TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL DEFAULT '',
    geo_country     TEXT    NOT NULL DEFAULT '',
    geo_city        TEXT    NOT NULL DEFAULT '',
    geo_isp         TEXT    NOT NULL DEFAULT '',
    is_threat       INTEGER NOT NULL DEFAULT 0,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    rdns            TEXT    NOT NULL DEFAULT '',
    integrity_hash  TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    facility        TEXT    NOT NULL DEFAULT 'local2',
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    hostname        TEXT    NOT NULL DEFAULT '',
    sender_ip       TEXT    NOT NULL DEFAULT '',
    sender_port     INTEGER NOT NULL DEFAULT 0,
    app_name        TEXT    NOT NULL DEFAULT '',
    proc_id         TEXT    NOT NULL DEFAULT '',
    msg_id          TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    raw_message     TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'unknown',
    log_category    TEXT    NOT NULL DEFAULT 'firewall',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    transport       TEXT    NOT NULL DEFAULT 'udp',
    source_ip       TEXT    NOT NULL DEFAULT '',
    dest_ip         TEXT    NOT NULL DEFAULT '',
    source_port     INTEGER NOT NULL DEFAULT 0,
    dest_port       INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    action          TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL DEFAULT '',
    geo_country     TEXT    NOT NULL DEFAULT '',
    geo_city        TEXT    NOT NULL DEFAULT '',
    geo_isp         TEXT    NOT NULL DEFAULT '',
    is_threat       INTEGER NOT NULL DEFAULT 0,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    rdns            TEXT    NOT NULL DEFAULT '',
    integrity_hash  TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS system_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    facility        TEXT    NOT NULL DEFAULT 'kern',
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    hostname        TEXT    NOT NULL DEFAULT '',
    sender_ip       TEXT    NOT NULL DEFAULT '',
    sender_port     INTEGER NOT NULL DEFAULT 0,
    app_name        TEXT    NOT NULL DEFAULT '',
    proc_id         TEXT    NOT NULL DEFAULT '',
    msg_id          TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    raw_message     TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'unknown',
    log_category    TEXT    NOT NULL DEFAULT 'system',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    transport       TEXT    NOT NULL DEFAULT 'udp',
    source_ip       TEXT    NOT NULL DEFAULT '',
    dest_ip         TEXT    NOT NULL DEFAULT '',
    source_port     INTEGER NOT NULL DEFAULT 0,
    dest_port       INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    action          TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL DEFAULT '',
    geo_country     TEXT    NOT NULL DEFAULT '',
    geo_city        TEXT    NOT NULL DEFAULT '',
    geo_isp         TEXT    NOT NULL DEFAULT '',
    is_threat       INTEGER NOT NULL DEFAULT 0,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    rdns            TEXT    NOT NULL DEFAULT '',
    integrity_hash  TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS app_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    facility        TEXT    NOT NULL DEFAULT 'local4',
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    hostname        TEXT    NOT NULL DEFAULT '',
    sender_ip       TEXT    NOT NULL DEFAULT '',
    sender_port     INTEGER NOT NULL DEFAULT 0,
    app_name        TEXT    NOT NULL DEFAULT '',
    proc_id         TEXT    NOT NULL DEFAULT '',
    msg_id          TEXT    NOT NULL DEFAULT '',
    message         TEXT    NOT NULL DEFAULT '',
    raw_message     TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'unknown',
    log_category    TEXT    NOT NULL DEFAULT 'app',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    transport       TEXT    NOT NULL DEFAULT 'udp',
    source_ip       TEXT    NOT NULL DEFAULT '',
    dest_ip         TEXT    NOT NULL DEFAULT '',
    source_port     INTEGER NOT NULL DEFAULT 0,
    dest_port       INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    action          TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL DEFAULT '',
    geo_country     TEXT    NOT NULL DEFAULT '',
    geo_city        TEXT    NOT NULL DEFAULT '',
    geo_isp         TEXT    NOT NULL DEFAULT '',
    is_threat       INTEGER NOT NULL DEFAULT 0,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    rdns            TEXT    NOT NULL DEFAULT '',
    integrity_hash  TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

-- ── Indexes on all log tables ─────────────────────────────────────────────────
-- Covering indexes for the most common dashboard queries.

CREATE INDEX IF NOT EXISTS idx_auth_severity     ON auth_logs(severity);
CREATE INDEX IF NOT EXISTS idx_auth_received     ON auth_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_auth_hostname     ON auth_logs(hostname);
CREATE INDEX IF NOT EXISTS idx_auth_sender_ip    ON auth_logs(sender_ip);
CREATE INDEX IF NOT EXISTS idx_auth_event_type   ON auth_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_auth_username     ON auth_logs(username);
CREATE INDEX IF NOT EXISTS idx_auth_timestamp    ON auth_logs(timestamp);

CREATE INDEX IF NOT EXISTS idx_net_severity      ON network_logs(severity);
CREATE INDEX IF NOT EXISTS idx_net_received      ON network_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_net_hostname      ON network_logs(hostname);
CREATE INDEX IF NOT EXISTS idx_net_sender_ip     ON network_logs(sender_ip);
CREATE INDEX IF NOT EXISTS idx_net_device_type   ON network_logs(device_type);
CREATE INDEX IF NOT EXISTS idx_net_timestamp     ON network_logs(timestamp);

CREATE INDEX IF NOT EXISTS idx_fw_severity       ON firewall_logs(severity);
CREATE INDEX IF NOT EXISTS idx_fw_received       ON firewall_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_fw_hostname       ON firewall_logs(hostname);
CREATE INDEX IF NOT EXISTS idx_fw_sender_ip      ON firewall_logs(sender_ip);
CREATE INDEX IF NOT EXISTS idx_fw_action         ON firewall_logs(action);
CREATE INDEX IF NOT EXISTS idx_fw_source_ip      ON firewall_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dest_ip        ON firewall_logs(dest_ip);
CREATE INDEX IF NOT EXISTS idx_fw_timestamp      ON firewall_logs(timestamp);

CREATE INDEX IF NOT EXISTS idx_sys_severity      ON system_logs(severity);
CREATE INDEX IF NOT EXISTS idx_sys_received      ON system_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_sys_hostname      ON system_logs(hostname);
CREATE INDEX IF NOT EXISTS idx_sys_sender_ip     ON system_logs(sender_ip);
CREATE INDEX IF NOT EXISTS idx_sys_timestamp     ON system_logs(timestamp);

CREATE INDEX IF NOT EXISTS idx_app_severity      ON app_logs(severity);
CREATE INDEX IF NOT EXISTS idx_app_received      ON app_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_app_hostname      ON app_logs(hostname);
CREATE INDEX IF NOT EXISTS idx_app_app_name      ON app_logs(app_name);
CREATE INDEX IF NOT EXISTS idx_app_timestamp     ON app_logs(timestamp);

-- ── Unified view across all tables ───────────────────────────────────────────
-- Queries that need to search everything use this view.
-- The 'tbl' column lets you know which physical table a row came from.

DROP VIEW IF EXISTS all_logs;
CREATE VIEW all_logs AS
    SELECT id, timestamp, received_at, facility, severity, hostname,
           sender_ip, sender_port, app_name, proc_id, msg_id,
           message, raw_message, format, log_category, device_type,
           transport, source_ip, dest_ip, source_port, dest_port,
           protocol, username, action, event_type,
           geo_country, geo_city, geo_isp, is_threat, threat_score,
           rdns, integrity_hash, created_at,
           'auth_logs' AS tbl
    FROM auth_logs
UNION ALL
    SELECT id, timestamp, received_at, facility, severity, hostname,
           sender_ip, sender_port, app_name, proc_id, msg_id,
           message, raw_message, format, log_category, device_type,
           transport, source_ip, dest_ip, source_port, dest_port,
           protocol, username, action, event_type,
           geo_country, geo_city, geo_isp, is_threat, threat_score,
           rdns, integrity_hash, created_at,
           'network_logs' AS tbl
    FROM network_logs
UNION ALL
    SELECT id, timestamp, received_at, facility, severity, hostname,
           sender_ip, sender_port, app_name, proc_id, msg_id,
           message, raw_message, format, log_category, device_type,
           transport, source_ip, dest_ip, source_port, dest_port,
           protocol, username, action, event_type,
           geo_country, geo_city, geo_isp, is_threat, threat_score,
           rdns, integrity_hash, created_at,
           'firewall_logs' AS tbl
    FROM firewall_logs
UNION ALL
    SELECT id, timestamp, received_at, facility, severity, hostname,
           sender_ip, sender_port, app_name, proc_id, msg_id,
           message, raw_message, format, log_category, device_type,
           transport, source_ip, dest_ip, source_port, dest_port,
           protocol, username, action, event_type,
           geo_country, geo_city, geo_isp, is_threat, threat_score,
           rdns, integrity_hash, created_at,
           'system_logs' AS tbl
    FROM system_logs
UNION ALL
    SELECT id, timestamp, received_at, facility, severity, hostname,
           sender_ip, sender_port, app_name, proc_id, msg_id,
           message, raw_message, format, log_category, device_type,
           transport, source_ip, dest_ip, source_port, dest_port,
           protocol, username, action, event_type,
           geo_country, geo_city, geo_isp, is_threat, threat_score,
           rdns, integrity_hash, created_at,
           'app_logs' AS tbl
    FROM app_logs;

-- ── Devices registry ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL UNIQUE,
    hostname        TEXT    NOT NULL DEFAULT '',
    friendly_name   TEXT    NOT NULL DEFAULT '',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    mac_address     TEXT    NOT NULL DEFAULT '',
    vendor          TEXT    NOT NULL DEFAULT '',
    first_seen      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_seen       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_log_at     TEXT    NOT NULL DEFAULT '',
    msg_count       INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'unknown',
    ping_status     TEXT    NOT NULL DEFAULT 'unknown',
    ping_rtt_ms     REAL,
    last_ping       TEXT    NOT NULL DEFAULT '',
    notes           TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_devices_ip         ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_status     ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_type       ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen  ON devices(last_seen);

-- ── Alert rules ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT    NOT NULL DEFAULT '',
    condition_json  TEXT    NOT NULL DEFAULT '{}',
    action_json     TEXT    NOT NULL DEFAULT '{}',
    level           TEXT    NOT NULL DEFAULT 'medium',
    enabled         INTEGER NOT NULL DEFAULT 1,
    builtin         INTEGER NOT NULL DEFAULT 0,
    last_fired      TEXT,
    fire_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

-- ── Alert history ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         INTEGER NOT NULL REFERENCES alert_rules(id),
    rule_name       TEXT    NOT NULL DEFAULT '',
    level           TEXT    NOT NULL DEFAULT 'medium',
    reason          TEXT    NOT NULL DEFAULT '',
    fired_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    log_table       TEXT    NOT NULL DEFAULT '',
    log_id          INTEGER NOT NULL DEFAULT 0,
    device_ip       TEXT    NOT NULL DEFAULT '',
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    ack_by          TEXT    NOT NULL DEFAULT '',
    ack_at          TEXT,
    resolved        INTEGER NOT NULL DEFAULT 0,
    resolved_at     TEXT,
    notes           TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alert_hist_rule    ON alert_history(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_hist_fired   ON alert_history(fired_at);
CREATE INDEX IF NOT EXISTS idx_alert_hist_acked   ON alert_history(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alert_hist_level   ON alert_history(level);

-- ── Audit trail ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_trail (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    actor           TEXT    NOT NULL DEFAULT '',
    action          TEXT    NOT NULL DEFAULT '',
    target          TEXT    NOT NULL DEFAULT '',
    detail          TEXT    NOT NULL DEFAULT '',
    ip_address      TEXT    NOT NULL DEFAULT '',
    user_agent      TEXT    NOT NULL DEFAULT '',
    result          TEXT    NOT NULL DEFAULT 'success',
    session_id      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp    ON audit_trail(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor        ON audit_trail(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action       ON audit_trail(action);

-- ── Sessions ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token   TEXT    NOT NULL UNIQUE,
    username        TEXT    NOT NULL DEFAULT 'admin',
    role            TEXT    NOT NULL DEFAULT 'admin',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_active     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    expires_at      TEXT    NOT NULL,
    ip_address      TEXT    NOT NULL DEFAULT '',
    user_agent      TEXT    NOT NULL DEFAULT '',
    valid           INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_sessions_token     ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_valid     ON sessions(valid);
CREATE INDEX IF NOT EXISTS idx_sessions_expires   ON sessions(expires_at);

-- ── API keys ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    key_hash        TEXT    NOT NULL UNIQUE,
    key_prefix      TEXT    NOT NULL DEFAULT '',
    role            TEXT    NOT NULL DEFAULT 'viewer',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_used       TEXT,
    expires_at      TEXT,
    active          INTEGER NOT NULL DEFAULT 1,
    notes           TEXT    NOT NULL DEFAULT ''
);

-- ── Saved searches ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saved_searches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    query_json      TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    created_by      TEXT    NOT NULL DEFAULT 'admin',
    run_count       INTEGER NOT NULL DEFAULT 0,
    last_run        TEXT
);

-- ── Failover log ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS failover_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    event_type      TEXT    NOT NULL DEFAULT '',
    from_server     TEXT    NOT NULL DEFAULT '',
    to_server       TEXT    NOT NULL DEFAULT '',
    virtual_ip      TEXT    NOT NULL DEFAULT '',
    duration_sec    REAL,
    detail          TEXT    NOT NULL DEFAULT ''
);

-- ── Intake stats ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intake_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    packets_received INTEGER NOT NULL DEFAULT 0,
    packets_dropped  INTEGER NOT NULL DEFAULT 0,
    bytes_received   INTEGER NOT NULL DEFAULT 0,
    queue_depth      INTEGER NOT NULL DEFAULT 0,
    parse_errors     INTEGER NOT NULL DEFAULT 0,
    db_write_errors  INTEGER NOT NULL DEFAULT 0
);