"""Pin what `tools/collect_ctl.py` may claim about Microsoft's CTL cabinets: bytes and a digest, nothing more.

The collector decodes nothing. Its two checks are the `MSCF` magic and a SHA-256 of the exact bytes served,
and the digest is the pin `PLAN.md` quotes (`c0aa761f…` for `authrootstl.cab`). There is no expected digest
in the code to compare against: the pin is what a later reader, or a decoder fed the same bytes, compares
with. So "the pinned digest is checked" here means the recorded digest re-derives from the bytes the stub
served and from the cached file, and a different body yields a record that does not match the pin.

Offline: `urllib.request.urlopen` and `fetch` are replaced, and `--data` is a temporary directory.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import collect_ctl

# Bytes that start like a cabinet and are otherwise opaque: nothing here or in the collector reads past
# the magic, so a byte string is enough and no CAB is constructed.
CAB = b"MSCF" + b"\x00" * 4 + b"synthetic authroot cabinet"
OTHER_CAB = b"MSCF" + b"\x00" * 4 + b"a different cabinet"


class FakeResponse:
    def __init__(self, body: bytes, ctype: str = "application/vnd.ms-cab-compressed") -> None:
        self.body = body
        self.headers = {"Content-Type": ctype}

    def read(self, limit: int = -1) -> bytes:
        return self.body if limit < 0 else self.body[:limit]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def serve(monkeypatch: pytest.MonkeyPatch, bodies: dict[str, bytes | Exception]) -> list[str]:
    """Stub `urlopen` so each URL serves its body (or raises), and record what was asked for."""
    asked: list[str] = []

    def fake_urlopen(request: Any, timeout: float = 0.0) -> FakeResponse:
        url = request.full_url
        asked.append(url)
        body = bodies[url]
        if isinstance(body, Exception):
            raise body
        return FakeResponse(body)

    monkeypatch.setattr(collect_ctl.urllib.request, "urlopen", fake_urlopen)
    return asked


def run(monkeypatch: pytest.MonkeyPatch, data: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    monkeypatch.setattr(sys, "argv", ["collect_ctl.py", "--data", str(data), *extra])
    code = collect_ctl.main()
    doc = json.loads((data / "store" / "microsoft.ctl.json").read_text(encoding="utf-8"))
    return code, doc


def by_id(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["source_id"]: r for r in doc["sources"]}


@pytest.fixture
def two_urls(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    a, b = "http://ctl.invalid/a.cab", "http://ctl.invalid/b.cab"
    monkeypatch.setattr(
        collect_ctl, "SOURCES", {"windows.authroot_ctl": [a], "windows.disallowed_ctl": [b]}
    )
    return a, b


def test_cab_magic_and_pinned_digest_are_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, two_urls: tuple[str, str]
) -> None:
    a, b = two_urls
    pin = hashlib.sha256(CAB).hexdigest()

    # Wrong magic is refused by `fetch`, the next candidate is tried, and the refusal is kept.
    serve(monkeypatch, {a: b"<html>not a cabinet</html>", b: CAB})
    body, url, attempts, _ = collect_ctl.fetch([a, b])
    assert (body, url) == (CAB, b)
    assert len(attempts) == 1
    assert "not a CAB" in attempts[0]
    assert a in attempts[0]

    # The recorded digest is the SHA-256 of the served bytes, and the cache holds those same bytes.
    serve(monkeypatch, {a: CAB, b: OTHER_CAB})
    code, doc = run(monkeypatch, tmp_path)
    assert code == 0
    authroot = by_id(doc)["windows.authroot_ctl"]
    assert authroot["sha256"] == pin
    assert authroot["octets"] == len(CAB)
    assert authroot["transport"] == "http"
    assert authroot["decoded"] is False
    assert doc["counts"] == {"pinned": 2, "unavailable": 0, "certificates_enumerated": 0}
    cached = tmp_path / "raw" / "windows.authroot_ctl.cab"
    assert hashlib.sha256(cached.read_bytes()).hexdigest() == pin

    # A different body behind the same URL is a mismatch against the pin, and it shows as one.
    serve(monkeypatch, {a: OTHER_CAB, b: OTHER_CAB})
    code, doc = run(monkeypatch, tmp_path, "--refresh")
    assert code == 0
    assert by_id(doc)["windows.authroot_ctl"]["sha256"] != pin

    # A cache is re-hashed, not trusted: tampering with the file moves the recorded digest.
    cached.write_bytes(CAB)
    code, doc = run(monkeypatch, tmp_path)
    assert by_id(doc)["windows.authroot_ctl"]["sha256"] == pin
    cached.write_bytes(OTHER_CAB)
    code, doc = run(monkeypatch, tmp_path)
    assert by_id(doc)["windows.authroot_ctl"]["sha256"] != pin


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty-body"),
        pytest.param(b"MSC", id="truncated-inside-magic"),
        pytest.param(b"\x00" * 64, id="zeros"),
    ],
)
def test_hostile_fetch_ends_as_unavailable_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, two_urls: tuple[str, str], body: bytes
) -> None:
    a, b = two_urls
    serve(monkeypatch, {a: body, b: CAB})
    code, doc = run(monkeypatch, tmp_path)
    assert code == 1
    authroot = by_id(doc)["windows.authroot_ctl"]
    assert authroot["error"] == "unavailable"
    assert "sha256" not in authroot
    assert doc["counts"]["pinned"] == 1
    assert doc["counts"]["unavailable"] == 1
    assert not (tmp_path / "raw" / "windows.authroot_ctl.cab").exists()


def test_network_errors_and_an_oversized_body_are_refusals(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, two_urls: tuple[str, str]
) -> None:
    a, b = two_urls
    monkeypatch.setattr(collect_ctl, "MAX_BYTES", 16)
    serve(monkeypatch, {a: TimeoutError("timed out"), b: CAB + b"\x00" * 16})
    code, doc = run(monkeypatch, tmp_path)
    assert code == 1
    records = by_id(doc)
    assert records["windows.authroot_ctl"]["attempts"][0].startswith("TimeoutError")
    # The read stops at the cap, so hashing what came back would pin a truncation.
    assert "exceeds 16 octets" in records["windows.disallowed_ctl"]["attempts"][0]
    assert doc["counts"]["pinned"] == 0


@pytest.mark.parametrize(
    "cached_bytes", [b"", b"MSC", b"PK\x03\x04"], ids=["empty", "short", "zip"]
)
def test_a_cache_that_is_not_a_cab_is_not_pinned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, two_urls: tuple[str, str], cached_bytes: bytes
) -> None:
    a, b = two_urls
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "windows.authroot_ctl.cab").write_bytes(cached_bytes)
    asked = serve(monkeypatch, {a: CAB, b: CAB})
    code, doc = run(monkeypatch, tmp_path)
    assert code == 0
    authroot = by_id(doc)["windows.authroot_ctl"]
    assert a in asked
    assert authroot["sha256"] == hashlib.sha256(CAB).hexdigest()
    assert authroot["transport"] == "http"
    assert any("cache is not a CAB" in note for note in authroot["ruled_out"])


def test_a_cache_that_is_not_a_cab_and_no_fetch_ends_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, two_urls: tuple[str, str]
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "windows.authroot_ctl.cab").write_bytes(b"")
    monkeypatch.setattr(collect_ctl, "fetch", lambda _candidates: (b"", "", ["stubbed out"], None))
    code, doc = run(monkeypatch, tmp_path)
    assert code == 1
    authroot = by_id(doc)["windows.authroot_ctl"]
    assert authroot["error"] == "unavailable"
    assert authroot["attempts"][0].startswith("cache is not a CAB (0 octets)")
