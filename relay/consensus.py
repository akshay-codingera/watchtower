"""
relay/consensus.py
====================
WATCHTOWER — Split-Brain Prevention

With only two nodes, there's no real quorum to form — this module's
job is to make self-promotion (standby → primary) hard to trigger by
mistake, since the failure mode of promoting incorrectly (two primaries
writing to two SQLite files that then diverge) is worse than the
failure mode of staying standby a little too long.

Two independent safety checks, both must pass before a promotion is
considered safe:

    1. Peer unreachability must be *sustained*, not a single blip.
       ConsensusChecker.record_check() requires a run of consecutive
       failures over required_consecutive_failures checks before
       should_promote() returns True. Any single success resets the
       counter to zero.

    2. This node must confirm it isn't the one that's actually
       isolated. A standby that's lost its own uplink will also see
       the peer as "unreachable" — that's the classic split-brain
       trigger. verify_not_isolated() checks this node can still
       reach something other than the peer (its default gateway)
       before trusting its own view of the peer's state.

Neither check writes to the database — that's relay/failover_log.py's
job, driven by whatever calls this module (typically heartbeat.py's
on_transition handler in core.py).
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ConsensusState:
    consecutive_failures: int = 0
    last_check_at:        float = 0.0
    last_result:           bool = True   # True = peer was reachable


class ConsensusChecker:
    """
    Tracks peer reachability over time and gates promotion decisions.

    Args:
        peer_ip: The other WATCHTOWER node's IP (cfg.relay.peer_ip).
        required_consecutive_failures: How many consecutive failed
            checks are required before promotion is considered safe.
            Higher = slower failover, fewer false promotions. 3 is a
            reasonable default at a 5s check interval (~15s to react).
    """

    def __init__(self, peer_ip: str, required_consecutive_failures: int = 3) -> None:
        self._peer_ip = peer_ip
        self._required = required_consecutive_failures
        self._state = ConsensusState()

    def record_check(self, peer_reachable: bool) -> ConsensusState:
        """
        Record the result of one reachability check against the peer.
        Call this every heartbeat_interval alongside heartbeat.poll().

        Args:
            peer_reachable: Result of pinging/health-checking the peer.

        Returns:
            The updated ConsensusState.
        """
        self._state.last_check_at = time.time()
        self._state.last_result = peer_reachable

        if peer_reachable:
            if self._state.consecutive_failures > 0:
                logger.info("Peer %s reachable again — resetting failure streak", self._peer_ip)
            self._state.consecutive_failures = 0
        else:
            self._state.consecutive_failures += 1
            logger.warning(
                "Peer %s unreachable (%d/%d consecutive)",
                self._peer_ip, self._state.consecutive_failures, self._required
            )
        return self._state

    def should_promote(self) -> bool:
        """
        True once the peer has been unreachable for the required
        number of consecutive checks. Does NOT check self-isolation —
        call verify_not_isolated() as well before actually promoting.
        """
        return self._state.consecutive_failures >= self._required

    def verify_not_isolated(self, gateway_ip: str) -> bool:
        """
        Confirm this node itself still has network connectivity before
        trusting its view that the peer is down. If this node can't
        even reach its own gateway, the peer being "unreachable" tells
        you nothing about the peer — it tells you about yourself.

        Args:
            gateway_ip: An address this node should always be able to
                        reach if its own network is healthy — usually
                        the default gateway, not the peer.

        Returns:
            True if this node appears to have working connectivity
            (safe to trust its peer-unreachable observation).
            False means: do not promote, this node may be the one
            that's cut off.
        """
        if not gateway_ip:
            logger.warning("No gateway_ip configured for isolation check — refusing to confirm safety")
            return False

        reachable = self._ping(gateway_ip)
        if not reachable:
            logger.critical(
                "SPLIT-BRAIN GUARD: gateway %s unreachable — this node may be isolated. "
                "Refusing to confirm promotion is safe.",
                gateway_ip
            )
        return reachable

    def reset(self) -> None:
        """Clear the failure streak — call after a successful promotion or manual override."""
        self._state = ConsensusState()

    @property
    def state(self) -> ConsensusState:
        return self._state

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _ping(ip: str, timeout: int = 2) -> bool:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True, timeout=timeout + 2,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False