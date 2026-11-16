"""Read the certledger harvest tree already on disk.

JSON artifacts are opened: preserve cursors, signed heads, ``key-census.json``, CA catalogs,
``coverage/coverage-index-from-preserve.json``, and the log-list journal manifest. Shard,
tile, issuer DER, PEM, and checkpoint bytes are not. Those files are named and sized.
Nothing here parses a certificate, a ``.cle1`` shard, or a static-CT tile, and nothing is fetched.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}\Z")
_CATALOG = re.compile(r"ca-catalog-[A-Za-z0-9][A-Za-z0-9._-]*\.json\Z")
_MARKERS = ("entries", "heads", "leaf-shards", "coverage", "journal")
_READS = 3


class HarvestError(ValueError):
    """A path this reader will not open."""


@dataclass(frozen=True)
class FileStat:
    """One regular file under the data directory. ``size`` is ``st_size``; the bytes were not read."""

    name: str
    size: int


@dataclass(frozen=True)
class IssuerEdge:
    kind: str | None
    spki_sha256: str | None
    showings: int


@dataclass(frozen=True)
class CaRow:
    """One CA the catalog recorded, without ``der_b64``."""

    spki_sha256: str | None
    sha256: str | None
    ca: bool | None
    psc: bool | None
    der_bytes: int | None
    sightings: int
    issuers: tuple[IssuerEdge, ...]


@dataclass(frozen=True)
class CatalogSummary:
    name: str
    schema: str | None
    written_utc: str | None
    entries_read: int | None
    limits: tuple[str, ...]
    logs: tuple[tuple[str | None, str | None], ...]
    ca_count: int
    ca_true: int
    psc_true: int
    edge_kinds: tuple[tuple[str, int], ...]
    rows: tuple[CaRow, ...]
    error: str | None


def looks_like_harvest(data: str | Path) -> bool:
    """True when ``data`` holds a harvest layout rather than only trust-store artifacts."""
    root = Path(data)
    if not root.is_dir():
        return False
    if any((root / name).is_dir() for name in _MARKERS):
        return True
    artifacts = root / "artifacts"
    return artifacts.is_dir() and any(artifacts.glob("ca-catalog-*.json"))


class Harvest:
    """The harvest under one data directory (host ``D:\\data\\certledger``, container ``/data``)."""

    def __init__(self, data: str | Path) -> None:
        self.data = Path(data)
        if not self.data.is_dir():
            raise HarvestError(f"{self.data} is not a directory")

    def slugs(self, kind: str) -> tuple[str, ...]:
        """Directory names under ``entries``, ``heads``, ``leaf-shards``, or ``journal``."""
        if kind not in {"entries", "heads", "leaf-shards", "journal"}:
            raise HarvestError(f"unknown collection {kind!r}")
        folder = self.data / kind
        if not folder.is_dir() or folder.is_symlink():
            return ()
        names = []
        try:
            children: list[Path] = list(folder.iterdir())
        except OSError:
            return ()
        for child in children:
            if child.is_symlink() or not child.is_dir():
                continue
            if _SLUG.fullmatch(child.name):
                names.append(child.name)
        names.sort()
        return tuple(names)

    def cursor(self, slug: str) -> tuple[dict[str, Any] | None, str | None]:
        """``entries/<slug>/cursor.json``, or ``(None, reason)`` when it cannot be read."""
        path = self._under("entries", _slug(slug), "cursor.json")
        if not path.is_file():
            return None, "no cursor.json"
        return _read_json(path)

    def direct_files(self, slug: str) -> tuple[FileStat, ...]:
        """Files sitting next to ``cursor.json``. Directory children (tiles, issuers) are not listed."""
        self.ensure("entries", slug)
        return _files(self._dir("entries", slug))

    def shards(self, slug: str) -> tuple[FileStat, ...]:
        self.ensure("entries", slug)
        folder = self._dir("entries", slug)
        return tuple(
            item
            for item in _files(folder)
            if item.name.startswith("shard-") and item.name.endswith(".cle1")
        )

    def tiles(self, slug: str) -> tuple[FileStat, ...]:
        self.ensure("entries", slug)
        folder = self._dir("entries", slug) / "tiles"
        if not folder.is_dir() or folder.is_symlink():
            return ()
        return _files(folder)

    def issuers(self, slug: str) -> tuple[FileStat, ...]:
        self.ensure("entries", slug)
        folder = self._dir("entries", slug) / "issuers"
        if not folder.is_dir() or folder.is_symlink():
            return ()
        return _files(folder)

    def ensure(self, kind: str, slug: str) -> None:
        """Raise when ``kind``/``slug`` is not a directory in this tree."""
        if kind not in {"entries", "heads", "leaf-shards", "journal"}:
            raise HarvestError(f"unknown collection {kind!r}")
        folder = self._dir(kind, _slug(slug))
        if not folder.is_dir():
            raise HarvestError(f"no {kind} {slug!r}")

    def checkpoint_size(self, slug: str) -> int | None:
        """Size of a tiled log's checkpoint file. The bytes are not read."""
        self.ensure("entries", slug)
        path = self._under("entries", slug, "checkpoint")
        if path.is_symlink() or not path.is_file():
            return None
        try:
            return path.stat().st_size
        except OSError:
            return None

    def head_documents(
        self, slug: str
    ) -> tuple[tuple[str, dict[str, Any] | None, str | None], ...]:
        """Each ``heads/<slug>/*.json``. ``.raw`` is not opened."""
        folder = self._dir("heads", _slug(slug))
        if not folder.is_dir():
            raise HarvestError(f"no heads for {slug!r}")
        found: list[tuple[str, dict[str, Any] | None, str | None]] = []
        for item in _files(folder):
            if not item.name.endswith(".json"):
                continue
            doc, error = _read_json(folder / item.name)
            found.append((item.name, doc, error))
        return tuple(found)

    def head_files(self, slug: str) -> tuple[FileStat, ...]:
        """Every file under ``heads/<slug>``, including ``.raw``, by name and size only."""
        folder = self._dir("heads", _slug(slug))
        if not folder.is_dir():
            raise HarvestError(f"no heads for {slug!r}")
        return _files(folder)

    def census(self, slug: str) -> tuple[dict[str, Any] | None, str | None]:
        """``leaf-shards/<slug>/key-census.json``. Sibling PEM and ``census-state.json`` are not opened."""
        path = self._under("leaf-shards", _slug(slug), "key-census.json")
        if not path.is_file():
            return None, "no key-census.json"
        return _read_json(path)

    def census_files(self, slug: str) -> tuple[FileStat, ...]:
        folder = self._dir("leaf-shards", _slug(slug))
        if not folder.is_dir():
            raise HarvestError(f"no leaf-shards for {slug!r}")
        return _files(folder)

    def catalog_names(self) -> tuple[FileStat, ...]:
        folder = self.data / "artifacts"
        if not folder.is_dir() or folder.is_symlink():
            return ()
        return tuple(item for item in _files(folder) if _CATALOG.fullmatch(item.name))

    def catalog(self, name: str) -> CatalogSummary:
        """One CA catalog with certificate bytes dropped. ``name`` is a single file name."""
        if not _CATALOG.fullmatch(name):
            raise HarvestError(f"not a CA catalog name: {name!r}")
        path = self._under("artifacts", name)
        if not path.is_file():
            raise HarvestError(f"no catalog {name}")
        doc, error = _read_json(path)
        if doc is None:
            return _empty_catalog(name, error or "unreadable")
        return _summarize_catalog(name, doc)

    def coverage(self) -> tuple[dict[str, Any] | None, str | None]:
        path = self.data / "coverage" / "coverage-index-from-preserve.json"
        if path.is_symlink() or not path.is_file():
            return None, "no coverage/coverage-index-from-preserve.json"
        try:
            path.resolve().relative_to(self.data.resolve())
        except ValueError:
            raise HarvestError("coverage path escapes the data directory") from None
        return _read_json(path)

    def journal_day(
        self, day: str
    ) -> tuple[tuple[FileStat, ...], dict[str, Any] | None, str | None]:
        """Files in one journal day, plus ``manifest.json`` when it parses. Signatures are not opened."""
        folder = self._dir("journal", _slug(day))
        if not folder.is_dir():
            raise HarvestError(f"no journal day {day!r}")
        files = _files(folder)
        manifest = folder / "manifest.json"
        if manifest.is_symlink() or not manifest.is_file():
            return files, None, "no manifest.json"
        doc, error = _read_json(manifest)
        return files, doc, error

    def _dir(self, *parts: str) -> Path:
        path = self.data.joinpath(*(_slug(part) for part in parts))
        if path.is_symlink():
            raise HarvestError("refusing a symlink")
        try:
            path.resolve().relative_to(self.data.resolve())
        except ValueError:
            raise HarvestError("outside the data directory") from None
        return path

    def _under(self, *parts: str) -> Path:
        return self._dir(*parts[:-1]).joinpath(_segment(parts[-1]))


def _slug(name: str) -> str:
    if not _SLUG.fullmatch(name):
        raise HarvestError(f"not a name in this tree: {name!r}")
    return name


def _segment(name: str) -> str:
    if name in {".", ".."} or "/" in name or "\\" in name or not name:
        raise HarvestError(f"not a file name: {name!r}")
    return name


def _files(folder: Path) -> tuple[FileStat, ...]:
    """One directory level. File bytes are not read."""
    if not folder.is_dir() or folder.is_symlink():
        return ()
    found: list[FileStat] = []
    try:
        children = list(folder.iterdir())
    except OSError:
        return ()
    for child in children:
        if child.is_symlink() or not child.is_file():
            continue
        try:
            size = child.stat().st_size
        except OSError:
            continue
        found.append(FileStat(child.name, size))
    found.sort(key=lambda item: item.name)
    return tuple(found)


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read one JSON object. A file being replaced is retried; a missing file is not."""
    if path.is_symlink():
        return None, "refusing a symlink"
    last = "unreadable"
    for attempt in range(_READS):
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None, "not found"
        except OSError:
            last = "unreadable"
        else:
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                last = "not valid JSON"
            except UnicodeError:
                return None, "not UTF-8"
            else:
                if isinstance(doc, dict):
                    return doc, None
                return None, "not a JSON object"
        if attempt + 1 < _READS:
            time.sleep(0.05)
    return None, last


def _summarize_catalog(name: str, doc: dict[str, Any]) -> CatalogSummary:
    raw_cas = doc.get("cas")
    cas = raw_cas if isinstance(raw_cas, list) else []
    rows: list[CaRow] = []
    kinds: dict[str, int] = {}
    ca_true = 0
    psc_true = 0
    for item in cas:
        if not isinstance(item, dict):
            continue
        row = _ca_row(item, kinds)
        rows.append(row)
        if row.ca is True:
            ca_true += 1
        if row.psc is True:
            psc_true += 1
    logs: list[tuple[str | None, str | None]] = []
    raw_logs = doc.get("logs")
    if isinstance(raw_logs, list):
        for item in raw_logs:
            if isinstance(item, dict):
                logs.append((_text(item.get("log_id")), _text(item.get("url"))))
    limits = doc.get("limits")
    limit_lines = (
        tuple(item for item in limits if isinstance(item, str)) if isinstance(limits, list) else ()
    )
    return CatalogSummary(
        name,
        _text(doc.get("schema")),
        _text(doc.get("written_utc")),
        _int(doc.get("entries_read")),
        limit_lines,
        tuple(logs),
        len(rows),
        ca_true,
        psc_true,
        tuple(sorted(kinds.items())),
        tuple(rows),
        None,
    )


def _ca_row(item: dict[str, Any], kinds: dict[str, int]) -> CaRow:
    edges: list[IssuerEdge] = []
    raw = item.get("issuers")
    if isinstance(raw, list):
        for edge in raw:
            if not isinstance(edge, dict):
                continue
            kind = _text(edge.get("kind"))
            if kind is not None:
                kinds[kind] = kinds.get(kind, 0) + 1
            showings = edge.get("showings")
            edges.append(
                IssuerEdge(
                    kind,
                    _text(edge.get("spki_sha256")),
                    len(showings) if isinstance(showings, list) else 0,
                )
            )
    sightings = item.get("sightings")
    flag_ca = item.get("ca")
    flag_psc = item.get("psc")
    return CaRow(
        _text(item.get("spki_sha256")),
        _text(item.get("sha256")),
        flag_ca if isinstance(flag_ca, bool) else None,
        flag_psc if isinstance(flag_psc, bool) else None,
        _int(item.get("der_bytes")),
        len(sightings) if isinstance(sightings, list) else 0,
        tuple(edges),
    )


def _empty_catalog(name: str, error: str) -> CatalogSummary:
    return CatalogSummary(name, None, None, None, (), (), 0, 0, 0, (), (), error)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value
