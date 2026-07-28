# WATCHTOWER — Device Configuration Log

Fill this in as you configure each device to forward logs to WATCHTOWER.
Do it at the time you configure the device, not after — you will not
remember the exact facility mapping or quirks three weeks later.

WATCHTOWER's collector address: `<fill in — the intake/listener.py UDP/TCP host:port>`
Default port: 514/UDP (RFC 3164), 6514/TCP+TLS if `tls_enabled = true`.

## Facility → category routing reference

From `nucleus/constants.py`'s `FACILITY_TO_CATEGORY` — this is the
convention already baked into the parser, so point devices at the
facility that lands them in the right table:

| Facility          | Category    | Table            |
|-------------------|-------------|------------------|
| `local0`, `local1` | network     | `network_logs`   |
| `local2`, `local3` | firewall    | `firewall_logs`  |
| `local4`–`local7` | app         | `app_logs`       |
| `auth`, `authpriv`, `audit` | auth | `auth_logs`     |
| `kern`, `daemon`, `cron`, etc. | system | `system_logs` |

If a device can't set a custom facility, it'll land in `system_logs` by
default via its native facility — still captured, just not pre-sorted.

---

## Device inventory

Copy this block per device as you configure it.

### `<device hostname/IP>`

- **Type:** `<cisco_switch / fortinet_firewall / linux_server / ...>` (see `DeviceType` in `nucleus/constants.py`)
- **Management IP:** `<ip>`
- **Location:** `<physical location / rack / room>`
- **Configured on:** `<date>`
- **Facility used:** `<e.g. local0>`
- **Transport:** `<udp / tcp / tls>`
- **SNMP community (if beacon/snmp_probe.py will poll it):** `<community string, or "not configured">`
- **Config commands applied:**
  ```
  <paste the exact commands you ran on the device>
  ```
- **Quirks / notes:**
  `<anything unusual — nonstandard timestamp format, missing hostname field, rate of log volume, etc.>`

---

## Reference: common vendor syslog config snippets

Fill in the real WATCHTOWER collector IP before using any of these.

### Cisco IOS / IOS-XE
```
logging host <watchtower-ip> transport udp port 514
logging trap informational
logging facility local0
logging source-interface <mgmt-interface>
```

### Generic Linux (rsyslog)
```
# /etc/rsyslog.d/60-watchtower.conf
*.* @<watchtower-ip>:514
# or for TCP:
*.* @@<watchtower-ip>:514
```

### pfSense
```
Status > System Logs > Settings > Remote Logging Options
  Enable Remote Logging: yes
  Remote log servers: <watchtower-ip>:514
  Remote Syslog Contents: check what you want forwarded
```

### FortiGate
```
config log syslogd setting
    set status enable
    set server "<watchtower-ip>"
    set port 514
    set facility local2
end
```

### Windows (via NXLog, once winevent.py is built)
```
# Placeholder — winevent.py parser doesn't exist yet (marked ⚪ in the
# original file tree). Don't configure Windows forwarding until it's built,
# or messages will land unparsed as plaintext/unknown format.
```
