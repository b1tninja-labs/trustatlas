"""The typed answers the library returns. Every one carries the evidence it was read from.

A record never says a certificate is trusted. It says a store's artifact lists it (`present`), lists it as a
distrust entry (`distrusted`), was read and does not list it (`absent`), or could not be consulted (`unread`), and
it names the artifact, its SHA-256 and its `retrieved_at`, so a caller can always ask where an answer came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

State = Literal["present", "absent", "distrusted", "unread"]
STATES: tuple[State, ...] = ("present", "absent", "distrusted", "unread")


@dataclass(frozen=True)
class Evidence:
    """One artifact an answer was read from: where it is under the data directory, its bytes' SHA-256, and when
    its collector says the source was retrieved."""

    path: str
    sha256: str
    artifact: str | None
    program: str | None
    retrieved_at: str | None
    method: str | None


@dataclass(frozen=True)
class Entry:
    """One certificate a store's artifact lists. Names are strings the source file or reader printed, never a
    parsed distinguished name; `spki_sha256` is filled only where an asn1core-derived artifact recorded it."""

    cert_sha256: str
    spki_sha256: str | None = None
    subject: str | None = None
    alias: str | None = None
    names: tuple[str, ...] = ()
    trust: tuple[tuple[str, str], ...] = ()
    substore: str | None = None


@dataclass(frozen=True)
class Store:
    """A store as the registry names it, with the entries its artifact lists. `role` is `distrust` for a store
    whose listing means the opposite of trust (the Windows `Disallowed` store)."""

    id: str
    kind: str | None
    origin: str | None
    role: Literal["trust", "distrust"]
    entries: tuple[Entry, ...]
    evidence: Evidence


@dataclass(frozen=True)
class StoreSummary:
    """One inventory line: a store that was read, with its count and evidence, or one that was not, with why."""

    id: str
    kind: str | None
    origin: str | None
    role: Literal["trust", "distrust"]
    read: bool
    anchors: int | None
    evidence: Evidence | None
    reason: str = ""


@dataclass(frozen=True)
class Inventory:
    """Every store the registry knows, read or not. An unread store is listed, never left out."""

    stores: tuple[StoreSummary, ...]
    registry: Evidence | None
    limits: tuple[str, ...] = ()

    @property
    def read(self) -> tuple[StoreSummary, ...]:
        return tuple(s for s in self.stores if s.read)

    @property
    def unread(self) -> tuple[StoreSummary, ...]:
        return tuple(s for s in self.stores if not s.read)


@dataclass(frozen=True)
class StoreAnswer:
    """What one store says about the queried certificate, key or name, and the evidence for it."""

    store: str
    state: State
    matches: tuple[Entry, ...] = ()
    evidence: Evidence | None = None
    reason: str = ""


@dataclass(frozen=True)
class AnchorAnswer:
    """Every store's answer to one query. `query` is (field, value); stores not examined appear as `unread`."""

    query: tuple[str, str]
    answers: tuple[StoreAnswer, ...]
    limits: tuple[str, ...] = field(default=())

    def where(self, state: State) -> tuple[StoreAnswer, ...]:
        return tuple(a for a in self.answers if a.state == state)

    @property
    def present(self) -> tuple[StoreAnswer, ...]:
        return self.where("present")

    @property
    def absent(self) -> tuple[StoreAnswer, ...]:
        return self.where("absent")

    @property
    def distrusted(self) -> tuple[StoreAnswer, ...]:
        return self.where("distrusted")

    @property
    def unread(self) -> tuple[StoreAnswer, ...]:
        return self.where("unread")
