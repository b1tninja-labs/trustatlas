"""Pin what `tools/collect_certdata.py` reads out of NSS's `certdata.txt`: how many anchors, with which trust bits.

The fixture is written here, in the layout the real dump uses: a `CKO_CERTIFICATE` object carrying the DER as
`MULTILINE_OCTAL` under `CKA_VALUE`, followed by a `CKO_NSS_TRUST` object with the same `CKA_LABEL` and the
`CKA_TRUST_* CK_TRUST CKT_NSS_*` lines. The "certificates" are opaque byte strings, not DER anyone decodes, so
only their SHA-256 matters. The digests are computed from those bytes here rather than copied from a run.

Offline: `urllib.request.urlopen` is replaced and `--data` is a temporary directory.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import collect_certdata

HEADER = """#
# Synthetic certdata.txt fragment written for this test; no object below is a real certificate.
#
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST
CKA_TOKEN CK_BBOOL CK_TRUE
CKA_LABEL UTF8 "Mozilla Builtin Roots"
"""


def der(marker: str) -> bytes:
    return b"\x30\x20" + marker.encode("ascii").ljust(32, b"\x00")


def octal(data: bytes) -> str:
    """`MULTILINE_OCTAL` body: `\\ooo` groups, sixteen to a line, then `END`."""
    groups = [f"\\{b:03o}" for b in data]
    lines = ["".join(groups[i : i + 16]) for i in range(0, len(groups), 16)]
    return "\n".join([*lines, "END"])


def certificate(label: str) -> str:
    return f"""
# Certificate "{label}"
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_TOKEN CK_BBOOL CK_TRUE
CKA_PRIVATE CK_BBOOL CK_FALSE
CKA_MODIFIABLE CK_BBOOL CK_FALSE
CKA_LABEL UTF8 "{label}"
CKA_CERTIFICATE_TYPE CK_CERTIFICATE_TYPE CKC_X_509
CKA_SUBJECT MULTILINE_OCTAL
{octal(b"subject " + label.encode())}
CKA_ID UTF8 "0"
CKA_SERIAL_NUMBER MULTILINE_OCTAL
{octal(b"\x02\x01\x01")}
CKA_VALUE MULTILINE_OCTAL
{octal(der(label))}
CKA_NSS_MOZILLA_CA_POLICY CK_BBOOL CK_TRUE
CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE
CKA_NSS_EMAIL_DISTRUST_AFTER CK_BBOOL CK_FALSE
"""


def trust(label: str, server: str, email: str, code: str = "MUST_VERIFY_TRUST") -> str:
    return f"""
# Trust for "{label}"
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_TOKEN CK_BBOOL CK_TRUE
CKA_PRIVATE CK_BBOOL CK_FALSE
CKA_MODIFIABLE CK_BBOOL CK_FALSE
CKA_LABEL UTF8 "{label}"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
{octal(hashlib.sha1(der(label), usedforsecurity=False).digest())}
CKA_ISSUER MULTILINE_OCTAL
{octal(b"issuer " + label.encode())}
CKA_SERIAL_NUMBER MULTILINE_OCTAL
{octal(b"\x02\x01\x01")}
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_{server}
CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_{email}
CKA_TRUST_CODE_SIGNING CK_TRUST CKT_NSS_{code}
CKA_TRUST_STEP_UP_APPROVED CK_BBOOL CK_FALSE
"""


# Three anchors with distinct trust, a distrust record with no certificate beside it, and a trailing
# anchor so the expected counts do not depend on which object the file happens to end with.
FRAGMENT = (
    HEADER
    + certificate("Alpha Root")
    + trust("Alpha Root", "TRUSTED_DELEGATOR", "TRUSTED_DELEGATOR")
    + certificate("Bravo Email Root")
    + trust("Bravo Email Root", "MUST_VERIFY_TRUST", "TRUSTED_DELEGATOR")
    + certificate("Charlie Root")
    + trust("Charlie Root", "TRUSTED_DELEGATOR", "MUST_VERIFY_TRUST")
    + trust("Distrusted Without Certificate", "NOT_TRUSTED", "NOT_TRUSTED", "NOT_TRUSTED")
    + certificate("Delta Root")
    + trust("Delta Root", "TRUSTED_DELEGATOR", "TRUSTED_DELEGATOR")
    + certificate("Echo Root")
    + trust("Echo Root", "MUST_VERIFY_TRUST", "MUST_VERIFY_TRUST")
    + certificate("Foxtrot Root")
)

EXPECTED = {
    "Alpha Root": ("TRUSTED_DELEGATOR", "TRUSTED_DELEGATOR"),
    "Bravo Email Root": ("MUST_VERIFY_TRUST", "TRUSTED_DELEGATOR"),
    "Charlie Root": ("TRUSTED_DELEGATOR", "MUST_VERIFY_TRUST"),
    "Delta Root": ("TRUSTED_DELEGATOR", "TRUSTED_DELEGATOR"),
    "Echo Root": ("MUST_VERIFY_TRUST", "MUST_VERIFY_TRUST"),
}


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, limit: int = -1) -> bytes:
        return self.body if limit < 0 else self.body[:limit]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def serve(monkeypatch: pytest.MonkeyPatch, bodies: dict[str, bytes | Exception]) -> None:
    def fake_urlopen(request: Any, timeout: float = 0.0, context: Any = None) -> FakeResponse:
        body = bodies[request.full_url]
        if isinstance(body, Exception):
            raise body
        return FakeResponse(body)

    monkeypatch.setattr(collect_certdata.urllib.request, "urlopen", fake_urlopen)


def run(monkeypatch: pytest.MonkeyPatch, data: Path, *extra: str) -> int:
    monkeypatch.setattr(sys, "argv", ["collect_certdata.py", "--data", str(data), *extra])
    return collect_certdata.main()


def artifact(data: Path) -> dict[str, Any]:
    return json.loads((data / "store" / "mozilla.nss.json").read_text(encoding="utf-8"))


def test_fetch_yields_the_expected_anchor_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first, second = "https://certdata.invalid/a", "https://certdata.invalid/b"
    monkeypatch.setattr(collect_certdata, "URLS", (first, second))
    payload = FRAGMENT.encode("utf-8")
    serve(monkeypatch, {first: b"<html>404</html>", second: payload})

    assert run(monkeypatch, tmp_path, "--refresh") == 0
    doc = artifact(tmp_path)

    assert doc["provenance"]["source"] == second
    assert doc["provenance"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert (tmp_path / "raw" / "mozilla.nss.certdata.txt").read_bytes() == payload
    attempts = json.loads((tmp_path / "raw" / "mozilla.nss.certdata.attempts.json").read_text())
    assert attempts["won"] == second
    assert len(attempts["ruled_out"]) == 1

    # Six certificate objects; Foxtrot carries no trust object, so its bits are empty, not borrowed.
    assert doc["counts"] == {
        "certificates": 6,
        "stated_server_auth_trusted": 3,
        "unmatched_trust_objects": 1,
    }
    anchors = {a["subject"]: a for a in doc["anchors"]}
    assert set(anchors) == {*EXPECTED, "Foxtrot Root"}
    for label, (server, email) in EXPECTED.items():
        anchor = anchors[label]
        assert anchor["sha256"] == hashlib.sha256(der(label)).hexdigest(), label
        assert anchor["labels"] == [label]
        assert anchor["trust"] == {
            "SERVER_AUTH": server,
            "EMAIL_PROTECTION": email,
            "CODE_SIGNING": "MUST_VERIFY_TRUST",
        }, label
    assert anchors["Foxtrot Root"]["trust"] == {}
    assert any("Distrusted Without Certificate" in n for n in doc["notes"])


@pytest.mark.xfail(
    strict=True,
    reason="defect, not fixed: parse() never flushes a trust object that ends the file, so the last "
    "anchor in certdata.txt is recorded with trust {}; fixing it changes what the artifact records",
)
def test_a_trust_object_that_ends_the_file_is_kept() -> None:
    text = (
        HEADER + certificate("Last Root") + trust("Last Root", "TRUSTED_DELEGATOR", "NOT_TRUSTED")
    )
    by_hash, _ = collect_certdata.parse(text)
    (record,) = by_hash.values()
    assert record["trust"].get("SERVER_AUTH") == "TRUSTED_DELEGATOR"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty-body"),
        pytest.param(b"<!doctype html>", id="not-the-dump"),
        pytest.param(OSError("connection reset"), id="network-error"),
    ],
)
def test_a_hostile_fetch_exits_1_and_writes_no_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: bytes | Exception
) -> None:
    url = "https://certdata.invalid/only"
    monkeypatch.setattr(collect_certdata, "URLS", (url,))
    serve(monkeypatch, {url: body})
    assert run(monkeypatch, tmp_path, "--refresh") == 1
    assert not (tmp_path / "store" / "mozilla.nss.json").exists()
    assert not (tmp_path / "raw" / "mozilla.nss.certdata.txt").exists()


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(HEADER + certificate("Cut")[:-200], id="truncated-inside-octal"),
        pytest.param(
            HEADER + certificate("Bad").replace("\\060", "\\06x", 1), id="malformed-escape"
        ),
        pytest.param(HEADER + "CKA_VALUE MULTILINE_OCTAL\n", id="value-without-end"),
        pytest.param(
            HEADER + 'CKA_LABEL UTF8 "Empty"\nCKA_VALUE MULTILINE_OCTAL\nEND\n', id="empty"
        ),
    ],
)
def test_hostile_certdata_parses_without_crashing(text: str) -> None:
    by_hash, notes = collect_certdata.parse(text)
    for record in by_hash.values():
        assert len(record["sha256"]) == 64
    if "Empty" in text:
        assert by_hash == {}
        assert any("zero bytes" in n for n in notes)
