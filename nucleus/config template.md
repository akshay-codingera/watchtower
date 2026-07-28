# ============================================================
# WATCHTOWER — config.ini
# Enterprise Log Management & Network Monitoring Platform
#
# Copy this file to the project root as config.ini
# and fill in your values before starting the server.
# ============================================================

[server]
name        = WATCHTOWER
environment = production
debug       = false
log_level   = INFO

[intake]
udp_host    = 0.0.0.0
udp_port    = 5140
tcp_port    = 5141
tls_port    = 6514
tls_enabled = false
tls_cert    =
tls_key     =
queue_size  = 10000
rate_limit  = 1000
recv_buffer = 4194304

[ledger]
db_path                  = logs/syslog.db
fts_enabled              = true
wal_mode                 = true
retention_auth_days      = 90
retention_network_days   = 60
retention_firewall_days  = 90
retention_system_days    = 30
retention_app_days       = 30

[auth]
# Generate with: python -c "import hashlib; print(hashlib.sha256(b'your_password').hexdigest())"
admin_password_hash = REPLACE_WITH_SHA256_HASH
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
secret_key          = REPLACE_WITH_RANDOM_SECRET
session_lifetime    = 28800
max_failed_logins   = 5
lockout_duration    = 300

[relay]
enabled             = false
role                = standalone
peer_ip             =
virtual_ip          =
heartbeat_interval  = 1
sync_interval       = 5

[scheduler]
enabled             = true
backup_hour         = 2
retention_hour      = 3
digest_hour         = 7
snmp_poll_interval  = 300

[notifications]
email_enabled       = false
smtp_host           =
smtp_port           = 587
smtp_user           =
smtp_password       =
alert_recipients    =
telegram_enabled    = false
telegram_token      =
telegram_chat_id    =
webhook_enabled     = false
webhook_url         =

[beacon]
ping_interval       = 30
ping_timeout        = 2
offline_threshold   = 900
silent_threshold    = 300
arp_scan_enabled    = false
snmp_enabled        = false
snmp_community      = public
subnet              =