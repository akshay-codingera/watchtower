"""
beacon/herald.py
=================
WATCHTOWER — Device Registration & Log-Activity Status

Two responsibilities:

1. register_from_log() — called once per LogRecord as it moves through
   the pipeline. Upserts the sending device into the registry via
   scribe.upsert_device(), auto-classifying it with Cartographer when
   there isn't already a confident device_type on file.

2. sweep_log_status() — called on a schedule. Demotes devices from
   online → silent → offline purely based on how long it's been since
   their last log (nucleus.constants DEVICE_SILENT_THRESHOLD_SEC /
   DEVICE_OFFLINE_THRESHOLD_SEC). This is deliberately independent of
   sonar.py's ICMP ping_status — see sonar.py's module docstring for
   why the two axes are kept separate.

Design principle: register_from_log() must be cheap enough to call on
every single ingested message without becoming the pipeline's
bottleneck. It does exactly one upsert — no SNMP, no ARP, no
classification work beyond a quick Cartographer.classify() call using
evidence that's already on hand (hostname + syslog format). Heavier
discovery (SNMP sysDescr, MAC vendor) happens separately in
snmp_probe.py / arp_scout.py and can be merged in later via
scribe.upsert_device() again — it's idempotent on IP.
"""

from __future__ import annotations

import datetime
import logging

from nucleus.constants import DeviceStatus, DeviceType, DEVICE_SILENT_THRESHOLD_SEC, DEVICE_OFFLINE_THRESHOLD_SEC
from nucleus.record import LogRecord, DeviceRecord
from nucleus.telemetry import metrics
from ledger.scribe import Scribe
from ledger.archivist import Archivist
from beacon.cartographer import Cartographer, ClassificationEvidence

logger = logging.getLogger(__name__)


class Herald:
    """
    Device lifecycle manager driven by syslog traffic.

    Args:
        scribe:       Scribe instance for writes.
        archivist:    Archivist instance for reads (used by the sweep).
        cartographer: Optional Cartographer instance. A default one is
                      created if not supplied.
    """

    def __init__(
        self,
        scribe: Scribe,
        archivist: Archivist,
        cartographer: Cartographer | None = None,
    ) -> None:
        self._scribe    = scribe
        self._archivist = archivist
        self._cartographer = cartographer or Cartographer()

    def register_from_log(self, record: LogRecord) -> None:
        """
        Upsert the device that sent `record` into the registry.

        Called by the pipeline for every ingested LogRecord (typically
        right after sentinel.py seals it, before or alongside the
        scribe.write() call). Cheap — one upsert, no network I/O.

        Args:
            record: A sealed LogRecord. Uses sender_ip as the device
                    key; hostname and format are used as weak
                    classification evidence if the device is new.
        """
        if not record.sender_ip:
            return  # nothing to key the device on

        existing = self._archivist.fetch_device(record.sender_ip)
        device_type = existing["device_type"] if existing else DeviceType.UNKNOWN

        # Only spend effort classifying if we don't already have a
        # confident type on file — avoids re-running this on every
        # single message from an already-known device.
        if device_type == DeviceType.UNKNOWN:
            evidence = ClassificationEvidence(
                hostname=record.hostname,
                syslog_format=record.format,
            )
            device_type = self._cartographer.classify(evidence)

        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        is_new = existing is None

        device = DeviceRecord(
            ip=record.sender_ip,
            hostname=record.hostname or (existing or {}).get("hostname", ""),
            device_type=device_type,
            log_category=record.log_category,
            first_seen=now,
            last_seen=now,
            status=DeviceStatus.ONLINE,
        )
        self._scribe.upsert_device(device)

        if is_new:
            metrics.beacon_new_devices.increment()
            logger.info(
                "New device registered: %s (%s, type=%s)",
                record.sender_ip, record.hostname or "no hostname", device_type
            )

    def sweep_log_status(self) -> dict:
        """
        Walk every known device and demote its status based on how
        long it's been since its last log, per the thresholds in
        nucleus.constants. Call on a schedule (e.g. every 60s).

        Transitions:
            < DEVICE_SILENT_THRESHOLD_SEC   → online
            < DEVICE_OFFLINE_THRESHOLD_SEC  → silent
            >= DEVICE_OFFLINE_THRESHOLD_SEC → offline

        Devices with no last_log_at at all are left as 'unknown' —
        they've been discovered (e.g. via ARP) but never logged.

        Returns:
            Summary dict: {checked, online, silent, offline, updated}.
        """
        devices = self._archivist.fetch_devices()
        now = datetime.datetime.utcnow()

        counts = {"online": 0, "silent": 0, "offline": 0, "unknown": 0}
        updated = 0

        for device in devices:
            last_log_at = device.get("last_log_at") or ""
            if not last_log_at:
                counts["unknown"] += 1
                continue

            try:
                last_seen_dt = datetime.datetime.strptime(last_log_at, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                counts["unknown"] += 1
                continue

            age_sec = (now - last_seen_dt).total_seconds()

            if age_sec < DEVICE_SILENT_THRESHOLD_SEC:
                new_status = DeviceStatus.ONLINE
            elif age_sec < DEVICE_OFFLINE_THRESHOLD_SEC:
                new_status = DeviceStatus.SILENT
            else:
                new_status = DeviceStatus.OFFLINE

            counts[new_status] += 1

            if device.get("status") != new_status:
                self._scribe.update_device_status(device["ip"], new_status)
                updated += 1

        metrics.beacon_devices_known.set(len(devices))
        metrics.beacon_devices_online.set(counts["online"])
        metrics.beacon_devices_offline.set(counts["offline"])

        logger.info(
            "Log-status sweep: %d devices — %d online, %d silent, %d offline, %d unknown (%d updated)",
            len(devices), counts["online"], counts["silent"], counts["offline"],
            counts["unknown"], updated
        )

        return {
            "checked": len(devices),
            "online":  counts["online"],
            "silent":  counts["silent"],
            "offline": counts["offline"],
            "unknown": counts["unknown"],
            "updated": updated,
        }