"""
ledger/
=======
WATCHTOWER persistent storage layer.

The ledger owns everything that touches the database.
No other layer reads or writes SQLite directly.

Public interface:
    from ledger.vault     import Vault
    from ledger.scribe    import Scribe
    from ledger.archivist import Archivist, LogFilter
    from ledger.indexer   import Indexer
    from ledger.retention import RetentionManager

Typical startup sequence in core.py:
    vault     = Vault(cfg.ledger.db_path)
    vault.initialise()           # runs migrations, verifies connectivity
    scribe    = Scribe(vault)
    archivist = Archivist(vault)
    indexer   = Indexer(vault)
    retention = RetentionManager(vault, cfg.ledger.retention_days, cfg.ledger.db_path)
"""

from ledger.vault     import Vault
from ledger.scribe    import Scribe
from ledger.archivist import Archivist, LogFilter
from ledger.indexer   import Indexer
from ledger.retention import RetentionManager

__all__ = [
    "Vault",
    "Scribe",
    "Archivist",
    "LogFilter",
    "Indexer",
    "RetentionManager",
]