"""
beacon/
=======
WATCHTOWER network awareness / agentless discovery layer.

Beacon owns everything that knows about devices as network entities,
as opposed to ledger/ which only knows about the logs they sent.
Nothing outside beacon/ talks to arp/snmp/ping directly.

Public interface:
    from beacon.cartographer import Cartographer, ClassificationEvidence
    from beacon.arp_scout    import ARPScout, ARPEntry
    from beacon.snmp_probe   import SNMPProbe, InterfaceStats
    from beacon.sonar        import Sonar, PingResult
    from beacon.herald       import Herald
    from beacon.topology     import TopologyMapper, NeighborEdge

Two independent status axes on the devices table, both written here:
    status       — driven by log activity, owned by herald.py
    ping_status  — driven by ICMP reachability, owned by sonar.py

Typical wiring in core.py / scheduler jobs:
    vault      = Vault(cfg.ledger.db_path)
    scribe     = Scribe(vault)
    archivist  = Archivist(vault)

    cartographer = Cartographer()
    herald       = Herald(scribe, archivist, cartographer)
    sonar        = Sonar(scribe, archivist)
    arp_scout    = ARPScout(subnet_filter=cfg.beacon.subnet)
    snmp_probe   = SNMPProbe(community=cfg.beacon.snmp_community)
    topology     = TopologyMapper(snmp_probe)

    # Called per-message from the pipeline (cheap):
    herald.register_from_log(record)

    # Called on a schedule (scheduler/jobs/*):
    herald.sweep_log_status()                    # every ~60s
    if cfg.beacon.arp_scan_enabled:
        arp_scout.scan()                          # every few minutes
    if cfg.beacon.snmp_enabled:
        sonar.sweep()                             # every cfg.beacon.ping_interval
        topology.build_graph(archivist.fetch_devices())  # hourly-ish, heavier
"""

from beacon.cartographer import Cartographer, ClassificationEvidence
from beacon.arp_scout    import ARPScout, ARPEntry
from beacon.snmp_probe   import SNMPProbe, InterfaceStats
from beacon.sonar        import Sonar, PingResult
from beacon.herald       import Herald
from beacon.topology     import TopologyMapper, NeighborEdge

__all__ = [
    "Cartographer",
    "ClassificationEvidence",
    "ARPScout",
    "ARPEntry",
    "SNMPProbe",
    "InterfaceStats",
    "Sonar",
    "PingResult",
    "Herald",
    "TopologyMapper",
    "NeighborEdge",
]