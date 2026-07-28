"""
relay/replicator.py
=====================
WATCHTOWER — Litestream Replication Monitor

Litestream itself runs continuously as its own systemd service
(deploy/keepalived/, deploy/systemd/) — it is not started, stopped, or
driven by this module. What this module does:

    1. Check whether the litestream process is actually alive
       (a silently-dead replicator is worse than no replicator —
       you find out at the worst possible moment otherwise).
    2. Trigger a restore on the standby when it needs to catch up
       before being promoted to primary (first boot, or after being
       offline long enough that its local DB copy is stale/missing).
    3. Report best-effort replication status for the health endpoint.

Design principle: replicator.py shells out to the `litestream` binary
rather than reimplementing any part of the protocol. If litestream
isn't installed, every method raises ReplicationError with a clear
message rather than failing silently — a standby that thinks it's
replicating when it isn't is a data-loss incident waiting to happen.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from nucleus.exceptions import ReplicationError

logger = logging.getLogger(__name__)


@dataclass
class ReplicationStatus:
    running:        bool
    db_path:        str = ""
    replica_url:    str = ""
    last_checked:   str = ""
    detail:         str = ""


class Replicator:
    """
    Litestream process and replication monitor.

    Args:
        db_path:       Path to the local SQLite database file being
                        replicated (cfg.ledger.db_path).
        litestream_config: Path to litestream's own YAML config, used
                        only to read the replica URL for status
                        reporting — never written to.
    """

    def __init__(self, db_path: str, litestream_config: str = "/etc/litestream.yml") -> None:
        self._db_path = db_path
        self._config_path = litestream_config

    def is_installed(self) -> bool:
        """True if the litestream binary is on PATH."""
        return shutil.which("litestream") is not None

    def is_running(self) -> bool:
        """
        Check whether a litestream process is currently running.

        Uses `pgrep` rather than parsing `litestream databases` output,
        since a hung-but-registered process is exactly the failure mode
        worth detecting separately from "not configured at all".
        """
        try:
            result = subprocess.run(
                ["pgrep", "-x", "litestream"],
                capture_output=True, text=True, timeout=3,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def status(self) -> ReplicationStatus:
        """
        Best-effort replication status snapshot for the health endpoint.

        Returns:
            ReplicationStatus. `running=False` with a `detail` message
            if litestream isn't installed, isn't running, or the
            `litestream databases` call fails — never raises.
        """
        import datetime
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        if not self.is_installed():
            return ReplicationStatus(running=False, db_path=self._db_path,
                                      last_checked=now, detail="litestream not installed")

        running = self.is_running()
        replica_url = self._read_replica_url()

        detail = "ok" if running else "litestream process not found"
        return ReplicationStatus(
            running=running, db_path=self._db_path, replica_url=replica_url,
            last_checked=now, detail=detail,
        )

    def restore(self, target_path: str | None = None, if_missing_only: bool = True) -> Path:
        """
        Restore the database from the replica — used when a standby is
        being promoted and its local copy is stale or absent.

        Args:
            target_path:     Where to restore to. Defaults to db_path.
            if_missing_only: If True (default) and a file already
                              exists at the target, skip the restore
                              and return the existing path untouched —
                              avoids clobbering a DB that's actually
                              current. Set False to force a fresh
                              restore (e.g. known-stale standby).

        Returns:
            Path to the restored (or pre-existing) database file.

        Raises:
            ReplicationError: If litestream isn't installed or the
                              restore subprocess fails.
        """
        self._require_binary()
        dest = Path(target_path or self._db_path)

        if if_missing_only and dest.exists():
            logger.info("Restore skipped — %s already exists", dest)
            return dest

        dest.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["litestream", "restore", "-config", self._config_path, "-o", str(dest), self._db_path]

        logger.info("Restoring database from replica: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            raise ReplicationError(f"litestream restore timed out: {exc}") from None

        if result.returncode != 0:
            raise ReplicationError(f"litestream restore failed: {result.stderr.strip()}")

        logger.info("Database restored to %s", dest)
        return dest

    def replica_generations(self) -> list[dict]:
        """
        List known replica generations (litestream's snapshot/WAL
        checkpoints) for diagnostics. Returns an empty list rather than
        raising if the query fails — this is diagnostic-only info.
        """
        self._require_binary()
        try:
            result = subprocess.run(
                ["litestream", "generations", "-config", self._config_path, self._db_path],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            logger.warning("Could not list replica generations: %s", exc)
            return []

        if result.returncode != 0:
            logger.warning("litestream generations failed: %s", result.stderr.strip())
            return []

        # Plain-text table output — parse conservatively, one row per
        # non-header line, whitespace-separated columns.
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        if len(lines) < 2:
            return []
        headers = lines[0].split()
        rows = []
        for line in lines[1:]:
            values = line.split()
            rows.append(dict(zip(headers, values)))
        return rows

    # ── Private helpers ───────────────────────────────────────────────────────

    def _require_binary(self) -> None:
        if not self.is_installed():
            raise ReplicationError(
                "litestream binary not found on PATH — see "
                "https://litestream.io/install/ or deploy/scripts/"
            )

    def _read_replica_url(self) -> str:
        """
        Best-effort read of the replica URL from litestream's YAML
        config, for status reporting only. Avoids a YAML dependency by
        doing a simple line scan rather than a full parse.
        """
        try:
            text = Path(self._config_path).read_text(encoding="utf-8")
        except OSError:
            return ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("url:"):
                return stripped.split(":", 1)[1].strip().strip('"').strip("'")
        return ""