"""
beacon/topology.py
====================
WATCHTOWER — LLDP Neighbor Discovery

Walks the standard LLDP-MIB on switches/routers that support it to
discover physical neighbor relationships, then assembles those edges
into a graph the portal's topology.js can render.

Design principle: this is genuinely best-effort. LLDP-MIB support and
exact table population varies across vendors (and some devices only
speak CDP, Cisco's proprietary predecessor, which isn't implemented
here — add a cdp.py-style parser alongside this if you hit a Cisco
device that needs it). Every neighbor lookup is wrapped so one
uncooperative device can't break a full topology scan.

Requires cfg.beacon.snmp_enabled and a device that responds to SNMP.
Devices that don't support LLDP-MIB simply contribute no edges — they
still appear as isolated nodes if beacon/herald.py has registered them.

LLDP-MIB reference (RFC-ish, IEEE 802.1AB):
    lldpRemTable: 1.0.8802.1.1.2.1.4.1.1
        .4  lldpRemChassisId       — usually the neighbor's MAC
        .7  lldpRemPortId          — neighbor's port identifier
        .8  lldpRemPortDesc        — human-readable port description
        .9  lldpRemSysName         — neighbor's hostname
        .10 lldpRemSysDesc         — neighbor's sysDescr
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from nucleus.exceptions import SNMPError
from beacon.snmp_probe import SNMPProbe

logger = logging.getLogger(__name__)

# LLDP-MIB lldpRemTable column OIDs (SNMPv2-SMI numeric form)
_OID_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.4"
_OID_REM_PORT_ID    = "1.0.8802.1.1.2.1.4.1.1.7"
_OID_REM_PORT_DESC  = "1.0.8802.1.1.2.1.4.1.1.8"
_OID_REM_SYS_NAME   = "1.0.8802.1.1.2.1.4.1.1.9"

# Local port cross-reference: lldpLocPortTable
_OID_LOC_PORT_DESC  = "1.0.8802.1.1.2.1.3.7.1.4"


@dataclass
class NeighborEdge:
    """One discovered link between two devices."""
    local_ip:      str
    local_port:    str = ""
    remote_ip:     str = ""     # usually unknown from LLDP alone — filled in
                                  # later if remote_sys_name resolves to a
                                  # known device IP
    remote_hostname: str = ""
    remote_port:   str = ""
    remote_chassis_id: str = ""


class TopologyMapper:
    """
    LLDP-based topology discovery.

    Args:
        probe: SNMPProbe instance to use for walks.
    """

    def __init__(self, probe: SNMPProbe) -> None:
        self._probe = probe

    def discover_neighbors(self, ip: str) -> list[NeighborEdge]:
        """
        Walk the LLDP remote-systems table on a single device.

        Args:
            ip: The device to query.

        Returns:
            List of NeighborEdge — empty if the device has no LLDP
            neighbors or doesn't support the MIB.
        """
        try:
            chassis_ids = self._probe.walk(ip, _OID_REM_CHASSIS_ID)
            port_ids    = self._probe.walk(ip, _OID_REM_PORT_ID)
            port_descs  = self._probe.walk(ip, _OID_REM_PORT_DESC)
            sys_names   = self._probe.walk(ip, _OID_REM_SYS_NAME)
        except SNMPError as exc:
            logger.debug("No LLDP data from %s: %s", ip, exc)
            return []

        if not chassis_ids:
            return []

        edges: list[NeighborEdge] = []
        for entry_idx in chassis_ids:
            # lldpRemTable indexes are composite (timeMark.localPortNum.remIndex),
            # so exact-match by the walk's own trailing index rather than trying
            # to decompose it further — good enough to pair columns together.
            edges.append(NeighborEdge(
                local_ip           = ip,
                remote_chassis_id  = chassis_ids.get(entry_idx, ""),
                remote_port        = port_descs.get(entry_idx) or port_ids.get(entry_idx, ""),
                remote_hostname    = sys_names.get(entry_idx, ""),
            ))

        logger.info("Discovered %d LLDP neighbor(s) on %s", len(edges), ip)
        return edges

    def build_graph(self, known_devices: list[dict]) -> dict:
        """
        Discover neighbors across every known device and assemble a
        graph structure ready for topology.js (nodes + edges).

        Args:
            known_devices: List of device dicts from
                            Archivist.fetch_devices() — must have 'ip'
                            and 'hostname' keys.

        Returns:
            {
                "nodes": [{"id": ip, "label": hostname}, ...],
                "edges": [{"from": ip, "to": ip_or_hostname, "local_port": ..., "remote_port": ...}, ...]
            }

            Edges whose remote_hostname matches a known device's
            hostname are resolved to that device's IP; otherwise the
            edge target falls back to the raw hostname/chassis ID
            string so the frontend can still render an external node.
        """
        hostname_to_ip = {
            d["hostname"]: d["ip"] for d in known_devices if d.get("hostname")
        }

        nodes = [{"id": d["ip"], "label": d.get("hostname") or d["ip"]} for d in known_devices]
        edges: list[dict] = []

        for device in known_devices:
            ip = device.get("ip", "")
            if not ip:
                continue
            for edge in self.discover_neighbors(ip):
                target = hostname_to_ip.get(edge.remote_hostname) or edge.remote_hostname or edge.remote_chassis_id
                if not target:
                    continue
                edges.append({
                    "from":        edge.local_ip,
                    "to":          target,
                    "local_port":  edge.local_port,
                    "remote_port": edge.remote_port,
                })

        logger.info("Topology graph: %d nodes, %d edges", len(nodes), len(edges))
        return {"nodes": nodes, "edges": edges}