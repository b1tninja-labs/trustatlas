"""Pin what `tools/probe_sources.py` writes to `sources/` (row `ta.probe_sources`).

Two properties make the catalog evidence rather than a log:

* every digest it records is the SHA-256 of the bytes that source served, so a stranger re-fetching the same
  bytes gets the same number (and the byte and PEM-block counts beside it agree);
* `sources/catalog.json` moves only on a full sweep. The data directory's README states the rule: a `--only`
  run writes its own timestamped catalog and leaves the canonical one alone, because a fragment must not
  replace a complete record.

Hermetic: `urlopen` is replaced by a table of canned bodies, so no request leaves the process, and the data
directory is `tmp_path`.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import probe_sources

PEM = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
ALL_URLS = [url for _sid, _group, urls in probe_sources.SOURCES for url in urls]

# The first NSS candidate is a wrong guess (404), so the second must win and both attempts must be kept.
NSS_FIRST, NSS_SECOND = next(
    urls for sid, _g, urls in probe_sources.SOURCES if sid == "mozilla.nss.certdata"
)[:2]
# Every ARIN candidate fails at the transport, so that source is recorded unavailable rather than dropped.
ARIN = next(urls for sid, _g, urls in probe_sources.SOURCES if sid == "rpki.arin.tal")
# One source is a generated page whose bytes change per request.
VOLATILE = next(urls for sid, _g, urls in probe_sources.SOURCES if sid == "apple.program_page")[0]


def body_for(url: str) -> bytes:
    """A fixed body per URL; curl's carries three PEM blocks so the count is not trivially zero."""
    blocks = 3 if url == "https://curl.se/ca/cacert.pem" else 0
    return f"# canned body for {url}\n".encode() + PEM * blocks


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 200
        self.headers = Message()
        self.headers["Content-Type"] = "text/plain; charset=utf-8"
        self._body = body

    def read(self, limit: int) -> bytes:
        return self._body[:limit]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeNetwork:
    def __init__(self) -> None:
        self.requested: list[str] = []
        self._tick = itertools.count()

    def __call__(self, request: urllib.request.Request, timeout: int, context: Any) -> FakeResponse:
        # The TLS context is the module's verifying default, and the UA is the one the catalog records.
        assert context is probe_sources.CTX
        assert request.get_header("User-agent") == probe_sources.UA
        url = request.full_url
        self.requested.append(url)
        if url == NSS_FIRST:
            raise urllib.error.HTTPError(url, 404, "Not Found", Message(), None)
        if url in ARIN:
            raise urllib.error.URLError("canned DNS failure")
        if url == VOLATILE:
            return FakeResponse(f"<html>render {next(self._tick)}</html>".encode())
        return FakeResponse(body_for(url))


def run(monkeypatch: pytest.MonkeyPatch, data: Path, *extra: str) -> tuple[int, FakeNetwork]:
    network = FakeNetwork()
    monkeypatch.setattr(probe_sources.urllib.request, "urlopen", network)
    monkeypatch.setattr(
        sys, "argv", ["probe_sources.py", "--data", str(data), "--retries", "1", *extra]
    )
    return probe_sources.main(), network


def test_committed_catalog_rehashes_to_its_recorded_digests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, network = run(monkeypatch, tmp_path)
    assert code == 0
    assert set(network.requested) <= set(ALL_URLS)

    sources = tmp_path / "sources"
    canonical = sources / "catalog.json"
    stamped = [p for p in sources.iterdir() if p.name != "catalog.json"]
    assert len(stamped) == 1
    # The canonical catalog is the full sweep's own record, byte for byte.
    assert canonical.read_bytes() == stamped[0].read_bytes()

    doc = json.loads(canonical.read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in doc["sources"]}
    assert sorted(rows) == sorted(sid for sid, _g, _u in probe_sources.SOURCES)
    assert doc["sources_total"] == len(probe_sources.SOURCES)
    assert doc["sources_available"] == sum(1 for r in rows.values() if r["available"])
    assert doc["sources_stable"] == sum(1 for r in rows.values() if r["stable"])

    for row in rows.values():
        if not row["available"] or not row["stable"]:
            continue
        # Re-fetching the same bytes yields the recorded numbers.
        served = body_for(row["url"])
        assert row["sha256"] == hashlib.sha256(served).hexdigest(), row["id"]
        assert row["second_sha256"] == row["sha256"], row["id"]
        assert row["bytes"] == len(served), row["id"]
        assert row["pem_blocks"] == served.count(b"BEGIN CERTIFICATE"), row["id"]
        winning = [a for a in row["attempts"] if a.get("url") == row["url"] and a.get("sha256")]
        assert winning, row["id"]
        assert winning[-1]["sha256"] == row["sha256"], row["id"]

    assert rows["curl.mozilla_bundle"]["pem_blocks"] == 3
    # A wrong guess is kept as an attempt, and the winner is the candidate after it.
    nss = rows["mozilla.nss.certdata"]
    assert nss["url"] == NSS_SECOND
    assert nss["statuses"] == [404, 200]
    # A source that answered nothing is recorded unavailable, with every attempt, rather than left out.
    arin = rows["rpki.arin.tal"]
    assert arin["available"] is False
    assert arin["sha256"] is None
    assert [a["url"] for a in arin["attempts"]] == ARIN
    # A page whose bytes move is available but not stable, and is not hashed into a claim of stability.
    apple = rows["apple.program_page"]
    assert apple["available"] is True
    assert apple["stable"] is False
    assert apple["second_sha256"] != apple["sha256"]


def test_an_only_sweep_does_not_move_the_canonical_catalog(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sources = tmp_path / "sources"
    sources.mkdir()
    canonical = sources / "catalog.json"
    before = b'{"kind": "trustatlas-source-catalog", "note": "a full sweep from earlier"}\n'
    canonical.write_bytes(before)

    code, network = run(monkeypatch, tmp_path, "--only", "curl.mozilla_bundle")
    assert code == 0
    assert (
        network.requested == ["https://curl.se/ca/cacert.pem"] * 2
    )  # the fetch and its stability check

    assert canonical.read_bytes() == before
    fragments = [p for p in sources.iterdir() if p.name != "catalog.json"]
    assert len(fragments) == 1
    assert fragments[0].name.startswith("catalog-")
    assert fragments[0].name.endswith("-curl.mozilla_bundle.json")
    fragment = json.loads(fragments[0].read_text(encoding="utf-8"))
    assert fragment["sources_total"] == 1
    assert [row["id"] for row in fragment["sources"]] == ["curl.mozilla_bundle"]


def test_an_unknown_only_id_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sources = tmp_path / "sources"
    sources.mkdir()
    canonical = sources / "catalog.json"
    canonical.write_bytes(b"{}\n")

    code, network = run(monkeypatch, tmp_path, "--only", "no.such.source")
    assert code == 2
    assert network.requested == []
    assert [p.name for p in sources.iterdir()] == ["catalog.json"]
    assert canonical.read_bytes() == b"{}\n"
