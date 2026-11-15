"""Read the artifacts the collectors wrote under a data directory, and answer questions across every store.

Nothing here fetches, parses a certificate or validates a path. A certificate is known by the SHA-256 its
collector recorded; a key by the SPKI SHA-256 that an asn1core-derived artifact (`<program>.spki.json`) recorded
for that certificate. The store list comes from `store/registry.status.json` (written by
`tools/store_registry.py --probe`), so a store the registry knows but nobody collected is reported `unread`
instead of disappearing; without that file the library falls back to every collector artifact under `store/`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path, PureWindowsPath
from typing import Any, Literal

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

# Collector artifact types whose listing is a store's membership. Joins, status files and catalogs are not stores.
STORE_ARTIFACTS = frozenset(
    {"trustatlas.bundle.collect", "trustatlas.certdata.collect", "trustatlas.store.collect"}
)
# Registry rows whose listing means distrust, not trust. Recorded by id because the registry's `kind` for the
# Windows Disallowed store is `os-store`, the same as Root.
DISTRUST_STORES = frozenset({"windows.disallowed"})
# Per-purpose trust values a source uses to state distrust. NSS writes `NOT_TRUSTED` (CKT_NSS_NOT_TRUSTED);
# `MUST_VERIFY_TRUST` only means "not a delegator for this purpose" and is not distrust.
DISTRUST_VALUES = frozenset({"NOT_TRUSTED", "DISTRUSTED"})
LIMITS = (
    "identity join only: membership of a certificate or key in a store's artifact, no path validation",
    "names are strings printed by the source or its reader, not parsed distinguished names",
    "a store that was not read is unread, never absent",
)
HEX64 = re.compile(r"[0-9a-f]{64}")


class AtlasError(ValueError):
    """A query or a data directory the library cannot answer from."""


class Atlas:
    """The stores under one data directory (`--data`: host `M:\\trustatlas`, container `/data`)."""

    def __init__(self, data: str | Path) -> None:
        self.data = Path(data)
        if not self.data.is_dir():
            raise AtlasError(f"{self.data} is not a directory")
        self._spki: dict[str, str] | None = None

    # -- public API ------------------------------------------------------------------------------------------

    def inventory(self) -> Inventory:
        """Every store the registry names, read or not, plus collector artifacts it does not name."""
        registry, rows = self._registry()
        out = [self._summary(row) for row in rows]
        named = {s.evidence.path for s in out if s.evidence is not None}
        for path in self._collector_artifacts():
            rel = self._rel(path)
            if rel not in named:
                doc = _load(path)
                out.append(self._summary({"id": str(doc.get("program") or path.stem)}, path))
        return Inventory(tuple(out), registry, LIMITS)

    def store(self, store_id: str) -> Store:
        """One store's entries and evidence. Raises AtlasError for a store that cannot be read."""
        row = self._row(store_id)
        loaded = self._read_row(row)
        if isinstance(loaded, str):
            raise AtlasError(f"{store_id}: {loaded}")
        return loaded

    def anchor(
        self,
        *,
        cert_sha256: str | None = None,
        spki_sha256: str | None = None,
        subject: str | None = None,
    ) -> AnchorAnswer:
        """Every store's answer for one certificate digest, one key digest, or a name substring (exactly one)."""
        given = [
            (k, v)
            for k, v in (
                ("cert_sha256", cert_sha256),
                ("spki_sha256", spki_sha256),
                ("subject", subject),
            )
            if v is not None
        ]
        if len(given) != 1:
            raise AtlasError("give exactly one of cert_sha256, spki_sha256 or subject")
        field, value = given[0]
        if field != "subject":
            value = value.strip().lower()
            if not HEX64.fullmatch(value):
                raise AtlasError(f"{field} must be 64 hex characters, not {value!r}")
        elif not value.strip():
            raise AtlasError("subject must not be empty")
        _, rows = self._registry()
        answers = [self._answer(row, field, value) for row in rows]
        named = {a.evidence.path for a in answers if a.evidence is not None}
        for path in self._collector_artifacts():
            if self._rel(path) not in named:
                doc = _load(path)
                answers.append(
                    self._answer({"id": str(doc.get("program") or path.stem)}, field, value, path)
                )
        return AnchorAnswer((field, value), tuple(answers), LIMITS)

    # -- reading ---------------------------------------------------------------------------------------------

    def _registry(self) -> tuple[Evidence | None, list[dict[str, Any]]]:
        path = self.data / "store" / "registry.status.json"
        if not path.is_file():
            return None, []
        doc = _load(path)
        rows = doc.get("stores")
        if not isinstance(rows, list):
            raise AtlasError(f"{path} has no list of stores")
        return self._evidence(path, doc), [r for r in rows if isinstance(r, dict) and r.get("id")]

    def _row(self, store_id: str) -> dict[str, Any]:
        _, rows = self._registry()
        for row in rows:
            if row["id"] == store_id:
                return row
        for path in self._collector_artifacts():
            doc = _load(path)
            if str(doc.get("program") or path.stem) == store_id:
                return {"id": store_id, "_path": str(path)}
        raise AtlasError(f"no store {store_id!r} under {self.data}")

    def _collector_artifacts(self) -> Iterator[Path]:
        folder = self.data / "store"
        if not folder.is_dir():
            return
        for path in sorted(folder.glob("*.json")):
            try:
                doc = _load(path)
            except AtlasError:
                continue
            if doc.get("artifact") in STORE_ARTIFACTS:
                yield path

    def _artifact_path(self, row: Mapping[str, Any]) -> Path | None:
        if row.get("_path"):
            return Path(str(row["_path"]))
        last = row.get("last_collection")
        named = last.get("artifact") if isinstance(last, dict) else None
        if not named:
            return None
        # The registry records the collector's own path (an absolute Windows path on the host). Resolve it by
        # name under this data directory, so the same artifacts read the same way from another mount.
        name = PureWindowsPath(str(named)).name
        return self.data / "store" / name

    def _read_row(self, row: Mapping[str, Any], path: Path | None = None) -> Store | str:
        path = path or self._artifact_path(row)
        if path is None:
            return "no artifact has been collected for this store"
        if not path.is_file():
            return (
                f"the artifact the registry names ({path.name}) is not under {self.data / 'store'}"
            )
        try:
            doc = _load(path)
        except AtlasError as error:
            return str(error)
        listed = doc.get("certificates")
        if not isinstance(listed, list):
            listed = doc.get("anchors")
        if not isinstance(listed, list):
            return f"{path.name} lists no certificates"
        substore = _substore(row.get("reader"))
        spki = self._spki_map()
        entries = []
        for item in listed:
            if not isinstance(item, dict) or not isinstance(item.get("sha256"), str):
                continue
            if substore is not None and item.get("store") != substore:
                continue
            entries.append(_entry(item, spki))
        store_id = str(row["id"])
        return Store(
            store_id,
            _text(row.get("kind")),
            _text(row.get("origin")),
            _role(store_id),
            tuple(entries),
            self._evidence(path, doc),
        )

    def _summary(self, row: Mapping[str, Any], path: Path | None = None) -> StoreSummary:
        store_id = str(row["id"])
        loaded = self._read_row(row, path)
        if isinstance(loaded, str):
            return StoreSummary(
                store_id,
                _text(row.get("kind")),
                _text(row.get("origin")),
                _role(store_id),
                False,
                None,
                None,
                loaded,
            )
        return StoreSummary(
            store_id,
            loaded.kind,
            loaded.origin,
            loaded.role,
            True,
            len(loaded.entries),
            loaded.evidence,
        )

    def _answer(
        self, row: Mapping[str, Any], field: str, value: str, path: Path | None = None
    ) -> StoreAnswer:
        loaded = self._read_row(row, path)
        store_id = str(row["id"])
        if isinstance(loaded, str):
            return StoreAnswer(store_id, "unread", reason=loaded)
        if field == "cert_sha256":
            matches = tuple(e for e in loaded.entries if e.cert_sha256 == value)
        elif field == "spki_sha256":
            matches = tuple(e for e in loaded.entries if e.spki_sha256 == value)
            unknown = sum(1 for e in loaded.entries if e.spki_sha256 is None)
            if not matches and unknown:
                return StoreAnswer(
                    store_id,
                    "unread",
                    evidence=loaded.evidence,
                    reason=f"{unknown} of {len(loaded.entries)} certificates here have no SPKI identity recorded, "
                    "so absence of the key cannot be stated",
                )
        else:
            needle = value.casefold()
            matches = tuple(
                e for e in loaded.entries if any(needle in n.casefold() for n in e.names)
            )
        if not matches:
            return StoreAnswer(store_id, "absent", evidence=loaded.evidence)
        state: State = (
            "distrusted"
            if loaded.role == "distrust" or any(_distrusts(e) for e in matches)
            else "present"
        )
        return StoreAnswer(store_id, state, matches, loaded.evidence)

    def _spki_map(self) -> dict[str, str]:
        """Certificate SHA-256 to SPKI SHA-256, from every `*.spki.json` asn1core-derived artifact. A key is a
        property of the certificate, so a digest recorded for one store applies wherever that certificate is."""
        if self._spki is None:
            found: dict[str, str] = {}
            for path in sorted(
                [*self.data.glob("*.spki.json"), *self.data.glob("store/*.spki.json")]
            ):
                try:
                    doc = _load(path)
                except AtlasError:
                    continue
                for item in doc.get("certificates") or ():
                    if isinstance(item, dict):
                        cert, key = item.get("sha256"), item.get("spki_sha256")
                        if isinstance(cert, str) and isinstance(key, str):
                            found[cert.lower()] = key.lower()
            self._spki = found
        return self._spki

    def _evidence(self, path: Path, doc: Mapping[str, Any]) -> Evidence:
        provenance = doc.get("provenance")
        method = provenance.get("method") if isinstance(provenance, dict) else None
        return Evidence(
            self._rel(path),
            hashlib.sha256(path.read_bytes()).hexdigest(),
            _text(doc.get("artifact")),
            _text(doc.get("program")),
            _text(doc.get("retrieved_at") or doc.get("probed_at") or doc.get("derived_at")),
            _text(method),
        )

    def _rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.data.resolve()).as_posix()
        except ValueError:
            return path.as_posix()


def _load(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AtlasError(f"{path.name} is not readable JSON: {error}") from None
    if not isinstance(doc, dict):
        raise AtlasError(f"{path.name} is not a JSON object")
    return doc


def _entry(item: Mapping[str, Any], spki: Mapping[str, str]) -> Entry:
    cert = str(item["sha256"]).lower()
    names = tuple(
        n
        for n in (
            _text(item.get("subject")),
            _text(item.get("alias")),
            _text(item.get("friendly_name")),
            *(_texts(item.get("labels"))),
        )
        if n
    )
    trust = item.get("trust")
    pairs = (
        tuple(sorted((str(k), str(v)) for k, v in trust.items())) if isinstance(trust, dict) else ()
    )
    own = item.get("spki_sha256")
    return Entry(
        cert,
        str(own).lower() if isinstance(own, str) else spki.get(cert),
        _text(item.get("subject")),
        _text(item.get("alias")),
        names,
        pairs,
        _text(item.get("store")),
    )


def _distrusts(entry: Entry) -> bool:
    return any(value in DISTRUST_VALUES for _, value in entry.trust)


def _role(store_id: str) -> Literal["trust", "distrust"]:
    return "distrust" if store_id in DISTRUST_STORES else "trust"


def _substore(reader: object) -> str | None:
    """`--store Disallowed` in a registry row's reader: the rows sharing `windows.machine.json` each read one."""
    if not isinstance(reader, list):
        return None
    for i, arg in enumerate(reader):
        if arg == "--store" and i + 1 < len(reader):
            return str(reader[i + 1])
        if isinstance(arg, str) and arg.startswith("--store="):
            return arg.split("=", 1)[1]
    return None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _texts(value: object) -> Iterable[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else ()
