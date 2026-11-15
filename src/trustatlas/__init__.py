"""trustatlas: which trust store lists which certificate or key, and how each answer is known.

    from trustatlas import Atlas

    atlas = Atlas("M:/trustatlas")          # the collectors' --data directory
    atlas.inventory()                       # every store the registry names, read or unread
    atlas.store("curl.mozilla_bundle")      # one store's entries and evidence
    atlas.anchor(spki_sha256="a02f...")     # every store: present / absent / distrusted / unread

The library reads artifacts that `tools/` collectors wrote; it fetches nothing, parses no certificate and validates
no path. Every answer carries the artifact, its SHA-256 and its `retrieved_at` (`trustatlas.records.Evidence`).
"""

from __future__ import annotations

from trustatlas.atlas import Atlas, AtlasError
from trustatlas.records import (
    AnchorAnswer,
    Entry,
    Evidence,
    Inventory,
    State,
    Store,
    StoreAnswer,
    StoreSummary,
)

__all__ = [
    "AnchorAnswer",
    "Atlas",
    "AtlasError",
    "Entry",
    "Evidence",
    "Inventory",
    "State",
    "Store",
    "StoreAnswer",
    "StoreSummary",
]
