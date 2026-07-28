-- =============================================================================
-- 002_integrity.sql
-- WATCHTOWER — Integrity and FTS5 Full-Text Search
-- =============================================================================
-- Adds:
--   1. integrity_log table for tracking tamper detection results
--   2. FTS5 virtual tables for full-text search across log messages
--   3. Triggers to keep FTS indexes in sync with log tables
-- =============================================================================

-- ── Integrity verification log ────────────────────────────────────────────────
-- Records the result of every integrity verification check.
-- When a log's SHA-256 hash is re-verified, the result goes here.

CREATE TABLE IF NOT EXISTS integrity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    log_table       TEXT    NOT NULL,
    log_id          INTEGER NOT NULL,
    stored_hash     TEXT    NOT NULL,
    computed_hash   TEXT    NOT NULL,
    tampered        INTEGER NOT NULL DEFAULT 0,
    checked_by      TEXT    NOT NULL DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS idx_integrity_tampered ON integrity_log(tampered);
CREATE INDEX IF NOT EXISTS idx_integrity_table    ON integrity_log(log_table);
CREATE INDEX IF NOT EXISTS idx_integrity_checked  ON integrity_log(checked_at);

-- ── FTS5 full-text search virtual tables ─────────────────────────────────────
-- FTS5 inverted indexes for sub-millisecond keyword search across millions
-- of log messages. Standard LIKE '%keyword%' scans every row — FTS5 does not.
--
-- content='' means this is a contentless FTS table — we store the rowid
-- mapping only, not the content. This saves disk space.
-- content_rowid='id' tells FTS5 which column is the primary key.

CREATE VIRTUAL TABLE IF NOT EXISTS fts_auth USING fts5(
    message,
    hostname,
    app_name,
    username,
    event_type,
    content='auth_logs',
    content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_network USING fts5(
    message,
    hostname,
    app_name,
    event_type,
    content='network_logs',
    content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_firewall USING fts5(
    message,
    hostname,
    app_name,
    action,
    event_type,
    content='firewall_logs',
    content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_system USING fts5(
    message,
    hostname,
    app_name,
    event_type,
    content='system_logs',
    content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_app USING fts5(
    message,
    hostname,
    app_name,
    event_type,
    content='app_logs',
    content_rowid='id'
);

-- ── Sync triggers — INSERT ────────────────────────────────────────────────────
-- Whenever a row is inserted into a log table, mirror it into the FTS index.

CREATE TRIGGER IF NOT EXISTS trg_fts_auth_insert
AFTER INSERT ON auth_logs BEGIN
    INSERT INTO fts_auth(rowid, message, hostname, app_name, username, event_type)
    VALUES (NEW.id, NEW.message, NEW.hostname, NEW.app_name, NEW.username, NEW.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_network_insert
AFTER INSERT ON network_logs BEGIN
    INSERT INTO fts_network(rowid, message, hostname, app_name, event_type)
    VALUES (NEW.id, NEW.message, NEW.hostname, NEW.app_name, NEW.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_firewall_insert
AFTER INSERT ON firewall_logs BEGIN
    INSERT INTO fts_firewall(rowid, message, hostname, app_name, action, event_type)
    VALUES (NEW.id, NEW.message, NEW.hostname, NEW.app_name, NEW.action, NEW.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_system_insert
AFTER INSERT ON system_logs BEGIN
    INSERT INTO fts_system(rowid, message, hostname, app_name, event_type)
    VALUES (NEW.id, NEW.message, NEW.hostname, NEW.app_name, NEW.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_app_insert
AFTER INSERT ON app_logs BEGIN
    INSERT INTO fts_app(rowid, message, hostname, app_name, event_type)
    VALUES (NEW.id, NEW.message, NEW.hostname, NEW.app_name, NEW.event_type);
END;

-- ── Sync triggers — DELETE ────────────────────────────────────────────────────
-- When retention.py deletes old rows, clean up FTS indexes too.

CREATE TRIGGER IF NOT EXISTS trg_fts_auth_delete
AFTER DELETE ON auth_logs BEGIN
    INSERT INTO fts_auth(fts_auth, rowid, message, hostname, app_name, username, event_type)
    VALUES ('delete', OLD.id, OLD.message, OLD.hostname, OLD.app_name, OLD.username, OLD.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_network_delete
AFTER DELETE ON network_logs BEGIN
    INSERT INTO fts_network(fts_network, rowid, message, hostname, app_name, event_type)
    VALUES ('delete', OLD.id, OLD.message, OLD.hostname, OLD.app_name, OLD.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_firewall_delete
AFTER DELETE ON firewall_logs BEGIN
    INSERT INTO fts_firewall(fts_firewall, rowid, message, hostname, app_name, action, event_type)
    VALUES ('delete', OLD.id, OLD.message, OLD.hostname, OLD.app_name, OLD.action, OLD.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_system_delete
AFTER DELETE ON system_logs BEGIN
    INSERT INTO fts_system(fts_system, rowid, message, hostname, app_name, event_type)
    VALUES ('delete', OLD.id, OLD.message, OLD.hostname, OLD.app_name, OLD.event_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_fts_app_delete
AFTER DELETE ON app_logs BEGIN
    INSERT INTO fts_app(fts_app, rowid, message, hostname, app_name, event_type)
    VALUES ('delete', OLD.id, OLD.message, OLD.hostname, OLD.app_name, OLD.event_type);
END;