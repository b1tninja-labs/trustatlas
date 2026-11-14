"""Pin that `tools/verify_provenance.py`'s exit code means something (`ROADMAP.md` row `ta.verify_provenance`).

The row's claim has three parts, and each is a test here: only `must` checks gate the exit code; a check that
could not run reports `unverifiable` and never `agree`; and an informational difference -- an installed
release lagging git head, a mirror behind its canonical server -- is reported as `differs` without turning the
run red.

Hermetic by design: the data directory is `tmp_path`, the certificates are synthetic byte strings (nothing here
decodes them, only their SHA-256 matters), and `verify_provenance.get` is replaced so no check can open a
socket. The checks themselves are the module's real `CHECKS` rows, selected by id, so a row whose `expect`
moved from `must` to `informational` would fail here rather than quietly widen what passes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import verify_provenance

BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"


def synthetic_der(marker: bytes) -> bytes:
    """A DER-shaped byte string carrying `marker`, so distinct anchors hash distinctly. Not a certificate."""
    body = bytes([0x30, 0x03, 0x02, 0x01, 0x01]) + marker + b"\x00" * (64 - len(marker))
    return bytes([0x30, len(body)]) + body


def pem(der: bytes, subject: str) -> str:
    b64 = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"# Subject: {subject}\n{BEGIN}\n{b64}\n{END}\n"


def digest(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


DER_A, DER_B, DER_C = (synthetic_der(m) for m in (b"anchor-a", b"anchor-b", b"anchor-c"))


def checks(*ids: str) -> tuple[dict[str, Any], ...]:
    by_id = {c["id"]: c for c in verify_provenance.CHECKS}
    return tuple(by_id[i] for i in ids)


def write_curl(data: Path, *, raw: list[bytes], claimed: list[bytes]) -> None:
    """Retain `raw` as raw/curl.pem and write a curl.json artifact that claims `claimed`."""
    (data / "raw").mkdir(parents=True, exist_ok=True)
    (data / "store").mkdir(parents=True, exist_ok=True)
    text = "".join(pem(der, f"CN=fixture {i}") for i, der in enumerate(raw))
    (data / "raw" / "curl.pem").write_text(text, encoding="utf-8")
    doc = {"program": "curl", "certificates": [{"sha256": digest(der)} for der in claimed]}
    (data / "store" / "curl.json").write_text(json.dumps(doc), encoding="utf-8")


def stub_get(payloads: dict[str, bytes | Exception]) -> Callable[..., bytes]:
    def fake(url: str, timeout: float = 120.0) -> bytes:
        answer = payloads.get(url, OSError(f"no stub for {url}"))
        if isinstance(answer, Exception):
            raise answer
        return answer

    return fake


def run(
    monkeypatch: pytest.MonkeyPatch,
    data: Path,
    rows: tuple[dict[str, Any], ...],
    payloads: dict[str, bytes | Exception] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Run `main()` over `rows` with every fetch stubbed, and read back the status artifact it wrote."""
    monkeypatch.setattr(verify_provenance, "CHECKS", rows)
    monkeypatch.setattr(verify_provenance, "get", stub_get(payloads or {}))
    monkeypatch.setattr(sys, "argv", ["verify_provenance.py", "--check", "--data", str(data)])
    code = verify_provenance.main()
    status = json.loads((data / "store" / "provenance.status.json").read_text(encoding="utf-8"))
    return code, status


def by_id(status: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in status["results"]}


def test_a_must_check_that_disagrees_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The extractor re-derives {A, B} from retained raw while the artifact claims {A, C}: the code moved under
    # the artifact, which is the Android mislabelling's shape, and `curl.internal_rederive` is a must check.
    write_curl(tmp_path, raw=[DER_A, DER_B], claimed=[DER_A, DER_C])
    rows = checks(
        "curl.internal_rederive",
        "curl.published_digest",
        "certifi.git_channel",
        "java.upstream_list",
    )
    published = rows[1]["url"]
    assert {r["id"]: r["expect"] for r in rows} == {
        "curl.internal_rederive": "must",
        "curl.published_digest": "must",
        "certifi.git_channel": "informational",
        "java.upstream_list": "informational",
    }
    code, status = run(
        monkeypatch,
        tmp_path,
        rows,
        # curl's published digest is unreachable and certifi's channel refuses: both must say so, not pass.
        {published: TimeoutError("timed out"), rows[2]["url"]: OSError("HTTP 404")},
    )

    results = by_id(status)
    assert code == 1
    assert status["gate_failures"] == ["curl.internal_rederive"]
    assert results["curl.internal_rederive"]["verdict"] == "differs"
    assert "added 1, dropped 1" in results["curl.internal_rederive"]["detail"]

    # A check that could not run is unverifiable, must or not -- never `agree`, and never silently absent.
    assert results["curl.published_digest"]["verdict"] == "unverifiable"
    assert "TimeoutError" in results["curl.published_digest"]["detail"]
    assert results["certifi.git_channel"]["verdict"] == "unverifiable"
    assert results["java.upstream_list"]["verdict"] == "unverifiable"
    assert len(status["results"]) == len(rows)
    assert "agree" not in status["counts"]
    assert status["counts"] == {"differs": 1, "unverifiable": 3}

    # The same run with the artifact repaired is green, so the 1 above is the disagreement and not the stubs.
    write_curl(tmp_path, raw=[DER_A, DER_B], claimed=[DER_A, DER_B])
    code, status = run(monkeypatch, tmp_path, rows, {published: TimeoutError("timed out")})
    assert code == 0
    assert status["gate_failures"] == []
    assert by_id(status)["curl.internal_rederive"]["verdict"] == "agree"


def test_a_published_digest_that_disagrees_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_curl(tmp_path, raw=[DER_A], claimed=[DER_A])
    row = checks("curl.published_digest")
    wrong = ("0" * 64 + "  cacert.pem\n").encode("ascii")
    code, status = run(monkeypatch, tmp_path, row, {row[0]["url"]: wrong})
    assert code == 1
    assert status["gate_failures"] == ["curl.published_digest"]

    right = digest((tmp_path / "raw" / "curl.pem").read_bytes())
    code, status = run(
        monkeypatch, tmp_path, row, {row[0]["url"]: f"{right}  cacert.pem\n".encode()}
    )
    assert code == 0
    assert by_id(status)["curl.published_digest"]["verdict"] == "agree"


def test_an_informational_difference_does_not_turn_red(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The two correct-but-different states the row names: an installed certifi release behind git head, and a
    # git mirror of certdata.txt behind Mercurial. Both differ; neither may gate. A commit_history check that
    # answered records rather than compares.
    write_curl(tmp_path, raw=[DER_A], claimed=[DER_A])
    (tmp_path / "raw" / "mozilla.nss.certdata.txt").write_bytes(b"# certdata as fetched from hg\n")
    (tmp_path / "store" / "certifi.json").write_text(
        json.dumps({"provenance": {"file_sha256": digest(b"the release on this machine")}}),
        encoding="utf-8",
    )
    rows = checks(
        "curl.internal_rederive", "certifi.git_channel", "nss.git_mirror", "certifi.git_authors"
    )
    history = [
        {
            "sha": "0123456789abcdef",
            "author": {"login": "github-actions[bot]"},
            "commit": {
                "author": {"name": "bot", "date": "2026-10-23T00:00:00Z"},
                "message": "release",
            },
        }
    ]
    code, status = run(
        monkeypatch,
        tmp_path,
        rows,
        {
            rows[1]["url"]: b"head of git, newer than the release",
            rows[2]["url"]: b"# certdata on a stale mirror\n",
            rows[3]["url"]: json.dumps(history).encode("utf-8"),
        },
    )
    results = by_id(status)
    assert results["certifi.git_channel"]["verdict"] == "differs"
    assert results["nss.git_mirror"]["verdict"] == "differs"
    assert results["certifi.git_authors"]["verdict"] == "recorded"
    assert results["curl.internal_rederive"]["verdict"] == "agree"
    assert status["gate_failures"] == []
    assert code == 0
