"""
relay/
======
WATCHTOWER high-availability layer (VRRP/Keepalived + Litestream).

Two nodes, one virtual IP, one SQLite file replicated primary→standby.
relay/ owns knowing which node is currently primary and making sure a
standby only ever promotes itself when it's genuinely safe to.

Only failover_log.py touches the ledger (via Scribe/Archivist) —
heartbeat.py, consensus.py, and replicator.py are pure logic / shell
out to `ip`, `ping`, and `litestream` respectively, and return plain
data for the caller to act on and log.

Public interface:
    from relay.heartbeat     import Heartbeat, RelayRole, RoleTransition
    from relay.consensus     import ConsensusChecker, ConsensusState
    from relay.replicator    import Replicator, ReplicationStatus
    from relay.failover_log  import FailoverLog

Typical wiring in core.py (runs on both nodes identically):
    vault      = Vault(cfg.ledger.db_path)
    scribe     = Scribe(vault)
    archivist  = Archivist(vault)

    failover_log = FailoverLog(scribe, archivist, this_server=socket.gethostname())
    consensus    = ConsensusChecker(cfg.relay.peer_ip)
    replicator   = Replicator(cfg.ledger.db_path)
    heartbeat    = Heartbeat(
        cfg.relay.virtual_ip,
        on_transition=lambda t: failover_log.record_transition(t, cfg.relay.virtual_ip),
    )

    if cfg.relay.enabled and cfg.relay.role == "standby":
        replicator.restore()   # catch up before serving anything

    # scheduler, every cfg.relay.heartbeat_interval seconds:
    heartbeat.poll()
    consensus.record_check(peer_reachable=ping(cfg.relay.peer_ip))

    if consensus.should_promote():
        if consensus.verify_not_isolated(gateway_ip=cfg.relay.gateway_ip):
            replicator.restore(if_missing_only=False)
            failover_log.record_promotion(
                from_server=cfg.relay.peer_ip,
                virtual_ip=cfg.relay.virtual_ip,
                reason=f"peer unreachable x{consensus.state.consecutive_failures}",
            )
            # ... take over the VIP (keepalived handles this once this
            #     process signals health via its check script) ...
        else:
            failover_log.record_promotion_refused(
                "gateway unreachable — possible self-isolation, not promoting"
            )
"""

from relay.heartbeat    import Heartbeat, RelayRole, RoleTransition
from relay.consensus    import ConsensusChecker, ConsensusState
from relay.replicator   import Replicator, ReplicationStatus
from relay.failover_log import FailoverLog

__all__ = [
    "Heartbeat",
    "RelayRole",
    "RoleTransition",
    "ConsensusChecker",
    "ConsensusState",
    "Replicator",
    "ReplicationStatus",
    "FailoverLog",
]