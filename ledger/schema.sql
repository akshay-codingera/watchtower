-- =============================================================================
-- schema.sql
-- WATCHTOWER — Master Schema Reference
-- =============================================================================
-- This file is the authoritative reference document for the complete
-- WATCHTOWER database schema. It is NOT executed directly by the application.
--
-- The actual schema is applied via the migration system:
--   ledger/migration/001_initial.sql   — all tables, indexes, views
--   ledger/migration/002_integrity.sql — FTS5 and integrity tables
--
-- This file exists so developers can see the entire schema in one place
-- without reading multiple migration files.
--
-- Last updated: v1.0 (migrations 001, 002)
-- =============================================================================

-- ── Log tables (5 category-partitioned tables) ────────────────────────────────
-- auth_logs, network_logs, firewall_logs, system_logs, app_logs
-- All share identical column structure.
-- Routed by LogRecord.log_category via CATEGORY_TABLE in nucleus/constants.py

-- ── Core log columns (identical across all 5 tables) ─────────────────────────
-- id              INTEGER PK AUTOINCREMENT
-- timestamp       TEXT    — timestamp from the syslog message itself
-- received_at     TEXT    — UTC time WATCHTOWER received the message
-- facility        TEXT    — kern/user/auth/local0/etc
-- severity        TEXT    — EMERG/ALERT/CRIT/ERROR/WARNING/NOTICE/INFO/DEBUG
-- hostname        TEXT    — hostname from the syslog message
-- sender_ip       TEXT    — actual IP that sent the UDP/TCP packet
-- sender_port     INTEGER — source port
-- app_name        TEXT    — application/process name
-- proc_id         TEXT    — process ID (RFC 5424)
-- msg_id          TEXT    — message ID (RFC 5424)
-- message         TEXT    — the log message body
-- raw_message     TEXT    — original unparsed string
-- format          TEXT    — rfc3164/rfc5424/cisco/fortinet/cef/json/unknown
-- log_category    TEXT    — auth/network/firewall/system/app
-- device_type     TEXT    — linux_server/cisco_router/fortinet_firewall/etc
-- transport       TEXT    — udp/tcp/tls/http
-- source_ip       TEXT    — IP extracted from message content
-- dest_ip         TEXT    — destination IP from message
-- source_port     INTEGER — source port from message
-- dest_port       INTEGER — destination port from message
-- protocol        TEXT    — tcp/udp/icmp from message
-- username        TEXT    — username if present
-- action          TEXT    — allow/block/deny (firewall logs)
-- event_type      TEXT    — specific event classification
-- geo_country     TEXT    — GeoIP country (enricher.py)
-- geo_city        TEXT    — GeoIP city
-- geo_isp         TEXT    — GeoIP ISP
-- is_threat       INTEGER — 0/1 threat intelligence flag
-- threat_score    INTEGER — 0-100 reputation score
-- rdns            TEXT    — reverse DNS of sender_ip
-- integrity_hash  TEXT    — SHA-256 of core fields (tamper detection)
-- created_at      TEXT    — row creation time (same as received_at usually)

-- ── all_logs view ────────────────────────────────────────────────────────────
-- UNION ALL of all 5 log tables.
-- Adds 'tbl' column so you know which physical table a row came from.
-- Use for cross-category queries. Use individual tables for category-specific.

-- ── devices ──────────────────────────────────────────────────────────────────
-- Registry of every known device. Populated by beacon/herald.py.
-- ip (UNIQUE), hostname, friendly_name, device_type, mac_address, vendor
-- first_seen, last_seen, last_log_at, msg_count, status
-- ping_status, ping_rtt_ms, last_ping, notes

-- ── alert_rules ──────────────────────────────────────────────────────────────
-- Defines alert conditions evaluated by dispatch/rulebook.py.
-- name (UNIQUE), description, condition_json, action_json
-- level, enabled, builtin, last_fired, fire_count

-- ── alert_history ────────────────────────────────────────────────────────────
-- Record of every fired alert. FK → alert_rules.id.
-- rule_id, rule_name, level, reason, fired_at
-- log_table, log_id, device_ip
-- acknowledged, ack_by, ack_at, resolved, resolved_at, notes

-- ── audit_trail ──────────────────────────────────────────────────────────────
-- Tamper-evident record of all admin actions.
-- actor, action, target, detail, ip_address, user_agent, result, session_id

-- ── sessions ─────────────────────────────────────────────────────────────────
-- Active admin sessions.
-- session_token (UNIQUE), username, role, created_at, last_active
-- expires_at, ip_address, user_agent, valid

-- ── api_keys ─────────────────────────────────────────────────────────────────
-- API key registry for programmatic access.
-- name (UNIQUE), key_hash (UNIQUE), key_prefix, role
-- created_at, last_used, expires_at, active, notes

-- ── saved_searches ───────────────────────────────────────────────────────────
-- Persistent saved search queries for the chronicle page.
-- name (UNIQUE), query_json, created_at, created_by, run_count, last_run

-- ── failover_log ─────────────────────────────────────────────────────────────
-- Record of HA failover events from relay/failover_log.py.
-- event_type, from_server, to_server, virtual_ip, duration_sec, detail

-- ── intake_stats ─────────────────────────────────────────────────────────────
-- Periodic snapshots of intake telemetry for historical trending.
-- recorded_at, packets_received, packets_dropped, bytes_received
-- queue_depth, parse_errors, db_write_errors

-- ── integrity_log ────────────────────────────────────────────────────────────
-- Results of SHA-256 integrity verification checks.
-- checked_at, log_table, log_id, stored_hash, computed_hash, tampered

-- ── FTS5 virtual tables ───────────────────────────────────────────────────────
-- fts_auth, fts_network, fts_firewall, fts_system, fts_app
-- content-linked to their respective log tables via content_rowid='id'
-- Maintained automatically by INSERT/DELETE triggers in 002_integrity.sql
-- Queried with: SELECT ... WHERE fts_auth MATCH 'keyword'