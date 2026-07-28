"""
nucleus/constants.py
====================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

All protocol-level constants for the syslog system.
RFC 3164, RFC 5424, and extended format mappings live here.
Nothing in this file has side effects — pure data only.
"""

# ── Syslog severity levels (RFC 5424 §6.2.1) ─────────────────────────────────
# Index position = severity code (0 = most severe, 7 = least)

SEVERITY_CODES: dict[str, int] = {
    "EMERG":   0,
    "ALERT":   1,
    "CRIT":    2,
    "ERROR":   3,
    "WARNING": 4,
    "NOTICE":  5,
    "INFO":    6,
    "DEBUG":   7,
}

SEVERITY_NAMES: list[str] = [
    "EMERG",    # 0 — system is unusable
    "ALERT",    # 1 — action must be taken immediately
    "CRIT",     # 2 — critical conditions
    "ERROR",    # 3 — error conditions
    "WARNING",  # 4 — warning conditions
    "NOTICE",   # 5 — normal but significant condition
    "INFO",     # 6 — informational messages
    "DEBUG",    # 7 — debug-level messages
]

# Severity aliases from real-world devices that deviate from RFC naming
SEVERITY_ALIASES: dict[str, str] = {
    "EMERGENCY":    "EMERG",
    "FATAL":        "EMERG",
    "ERR":          "ERROR",
    "WARN":         "WARNING",
    "INFORMATION":  "INFO",
    "INFORMATIONAL":"INFO",
    "TRACE":        "DEBUG",
    "VERBOSE":      "DEBUG",
    "CRITICAL":     "CRIT",
}

# Severity → dashboard display color (CSS variable names)
SEVERITY_COLORS: dict[str, str] = {
    "EMERG":   "#ef4444",   # red-500
    "ALERT":   "#ef4444",   # red-500
    "CRIT":    "#f87171",   # red-400
    "ERROR":   "#fb923c",   # orange-400
    "WARNING": "#f59e0b",   # amber-400
    "NOTICE":  "#3b82f6",   # blue-500
    "INFO":    "#22c55e",   # green-500
    "DEBUG":   "#6b7280",   # gray-500
}

# ── Syslog facility codes (RFC 5424 §6.2.1) ──────────────────────────────────
# Index position = facility code

FACILITY_NAMES: list[str] = [
    "kern",      # 0  — kernel messages
    "user",      # 1  — user-level messages
    "mail",      # 2  — mail system
    "daemon",    # 3  — system daemons
    "auth",      # 4  — security/authorization messages
    "syslog",    # 5  — messages generated internally by syslogd
    "lpr",       # 6  — line printer subsystem
    "news",      # 7  — network news subsystem
    "uucp",      # 8  — UUCP subsystem
    "cron",      # 9  — clock daemon
    "authpriv",  # 10 — security/authorization messages (private)
    "ftp",       # 11 — FTP daemon
    "ntp",       # 12 — NTP subsystem
    "audit",     # 13 — log audit
    "alert",     # 14 — log alert
    "clock",     # 15 — clock daemon (note 2)
    "local0",    # 16 — local use 0
    "local1",    # 17 — local use 1
    "local2",    # 18 — local use 2
    "local3",    # 19 — local use 3
    "local4",    # 20 — local use 4
    "local5",    # 21 — local use 5
    "local6",    # 22 — local use 6
    "local7",    # 23 — local use 7
]

FACILITY_CODES: dict[str, int] = {name: code for code, name in enumerate(FACILITY_NAMES)}

# Facility → log category mapping for routing to correct DB table
FACILITY_TO_CATEGORY: dict[str, str] = {
    "kern":     "system",
    "user":     "system",
    "mail":     "app",
    "daemon":   "system",
    "auth":     "auth",
    "syslog":   "system",
    "lpr":      "system",
    "news":     "app",
    "uucp":     "system",
    "cron":     "system",
    "authpriv": "auth",
    "ftp":      "app",
    "ntp":      "system",
    "audit":    "auth",
    "alert":    "system",
    "clock":    "system",
    "local0":   "network",   # convention: local0-1 = network devices
    "local1":   "network",
    "local2":   "firewall",  # convention: local2-3 = firewalls
    "local3":   "firewall",
    "local4":   "app",       # convention: local4-7 = applications
    "local5":   "app",
    "local6":   "app",
    "local7":   "app",
}

# ── Log format identifiers ────────────────────────────────────────────────────
# Returned by sieve.py to select the correct forge parser

class LogFormat:
    RFC3164    = "rfc3164"       # BSD syslog — most common
    RFC5424    = "rfc5424"       # IETF structured syslog
    CISCO      = "cisco"         # Cisco IOS %FACILITY-SEV-MNEMONIC
    FORTINET   = "fortinet"      # Fortinet key=value pairs
    PFSENSE    = "pfsense"       # pfSense filterlog
    CEF        = "cef"           # Common Event Format (Palo Alto, ArcSight)
    LEEF       = "leef"          # IBM LEEF (QRadar)
    WINEVENT   = "winevent"      # Windows Event Log via NXLog/WEF
    JSON       = "json"          # Structured JSON application logs
    PLAINTEXT  = "plaintext"     # Unstructured plain text
    UNKNOWN    = "unknown"       # Could not be identified

# ── Device type identifiers ───────────────────────────────────────────────────
# Set by cartographer.py during device classification

class DeviceType:
    LINUX_SERVER      = "linux_server"
    WINDOWS_SERVER    = "windows_server"
    WINDOWS_WORKSTATION = "windows_workstation"
    CISCO_ROUTER      = "cisco_router"
    CISCO_SWITCH      = "cisco_switch"
    CISCO_FIREWALL    = "cisco_firewall"
    FORTINET_FIREWALL = "fortinet_firewall"
    PFSENSE_FIREWALL  = "pfsense_firewall"
    PALO_ALTO         = "paloalto_firewall"
    HP_SWITCH         = "hp_switch"
    JUNIPER           = "juniper"
    ARUBA_AP          = "aruba_ap"
    UNIFI_AP          = "unifi_ap"
    PRINTER           = "printer"
    IP_CAMERA         = "ip_camera"
    APPLICATION       = "application"
    UNKNOWN           = "unknown"

# ── Log categories (DB table routing) ────────────────────────────────────────
class LogCategory:
    AUTH      = "auth"      # authentication, authorization events
    NETWORK   = "network"   # routing, switching, link events
    FIREWALL  = "firewall"  # traffic allow/block decisions
    SYSTEM    = "system"    # OS, kernel, daemon events
    APP       = "app"       # application logs

    ALL = [AUTH, NETWORK, FIREWALL, SYSTEM, APP]

# DB table name per category
CATEGORY_TABLE: dict[str, str] = {
    LogCategory.AUTH:     "auth_logs",
    LogCategory.NETWORK:  "network_logs",
    LogCategory.FIREWALL: "firewall_logs",
    LogCategory.SYSTEM:   "system_logs",
    LogCategory.APP:      "app_logs",
}

# ── Network and transport constants ───────────────────────────────────────────
class Transport:
    UDP_PORT      = 514     # standard syslog UDP
    TCP_PORT      = 514     # standard syslog TCP
    TLS_PORT      = 6514    # RFC 5425 syslog over TLS
    HTTP_PORT     = 5000    # WATCHTOWER dashboard
    SNMP_TRAP_PORT = 162    # SNMP trap receiver

    MAX_UDP_SIZE  = 65535   # maximum UDP datagram bytes
    RFC3164_MAX   = 1024    # RFC 3164 recommended maximum
    RFC5424_MAX   = 65535   # RFC 5424 maximum

# ── PRI formula constants ─────────────────────────────────────────────────────
PRI_FACILITY_MULTIPLIER = 8      # facility = PRI // 8
PRI_MAX                 = 191    # (23 * 8) + 7 = max valid PRI value
PRI_DEFAULT             = 13     # user.notice — used when PRI is absent

# ── Device status ─────────────────────────────────────────────────────────────
class DeviceStatus:
    ONLINE   = "online"    # sent a log in the last 5 minutes
    SILENT   = "silent"    # no log in 5-15 minutes — might be idle
    OFFLINE  = "offline"   # no log in 15+ minutes or ping failed
    UNKNOWN  = "unknown"   # never been pinged, no status yet

DEVICE_SILENT_THRESHOLD_SEC  = 300   # 5 minutes — move to silent
DEVICE_OFFLINE_THRESHOLD_SEC = 900   # 15 minutes — move to offline

# ── Alert levels ──────────────────────────────────────────────────────────────
class AlertLevel:
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

# ── RBAC roles ────────────────────────────────────────────────────────────────
class Role:
    ADMIN    = "admin"     # full access
    ANALYST  = "analyst"   # view logs, acknowledge alerts, no config
    VIEWER   = "viewer"    # read-only across all pages
    AUDITOR  = "auditor"   # audit trail and compliance only

# ── Session constants ─────────────────────────────────────────────────────────
SESSION_LIFETIME_SECONDS   = 28800   # 8 hours
MAX_FAILED_LOGINS          = 5       # lockout after this many failures
LOCKOUT_DURATION_SECONDS   = 300     # 5 minutes

# ── Integrity ─────────────────────────────────────────────────────────────────
INTEGRITY_HASH_FIELDS = [
    "timestamp", "hostname", "facility",
    "severity", "app_name", "message",
]   # fields included in SHA-256 integrity hash