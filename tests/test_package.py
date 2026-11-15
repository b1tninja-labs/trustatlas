"""The importable library (row `ta.package`): every answer names its evidence, an unexamined store is `unread`,
and a listing in a distrust store is reported as distrust. Synthetic artifacts only; nothing leaves `tmp_path`."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from trustatlas import Atlas, AtlasError
from trustatlas.records import STATES

A = "a" * 64
B = "b" * 64
C = "c" * 64
KEY_A = "1" * 64
KEY_C = "3" * 64


def write(path: Path, doc: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def bundle(
    program: str, *certs: dict[str, object], retrieved_at: str = "2026-11-14T00:00:00Z"
) -> dict[str, object]:
    return {
        "artifact": "trustatlas.bundle.collect",
        "program": program,
        "retrieved_at": retrieved_at,
        "provenance": {"method": "test fixture"},
        "certificates": list(certs),
    }


@pytest.fixture
def data(tmp_path: Path) -> Path:
    write(
        tmp_path / "store" / "curl.json",
        bundle(
            "curl",
            {"sha256": A, "subject": "Example Root A"},
            {"sha256": B, "subject": "Example Root B"},
        ),
    )
    write(
        tmp_path / "store" / "windows.machine.json",
        {
            "artifact": "trustatlas.store.collect",
            "program": "windows",
            "retrieved_at": "2026-11-13T00:00:00Z",
            "provenance": {"method": "PowerShell certificate provider"},
            "anchors": [
                {"sha256": A.upper(), "store": "Root", "subject": "CN=Example Root A"},
                {"sha256": C, "store": "Disallowed", "subject": "CN=Compromised C"},
            ],
        },
    )
    write(
        tmp_path / "store" / "mozilla.nss.json",
        {
            "artifact": "trustatlas.certdata.collect",
            "program": "mozilla.nss",
            "retrieved_at": "2026-11-12T00:00:00Z",
            "anchors": [
                {"sha256": B, "subject": "Example Root B", "trust": {"SERVER_AUTH": "NOT_TRUSTED"}},
                {
                    "sha256": C,
                    "subject": "Compromised C",
                    "trust": {"SERVER_AUTH": "MUST_VERIFY_TRUST"},
                },
            ],
        },
    )
    write(
        tmp_path / "curl.spki.json",
        {
            "artifact": "trustatlas.spki_identity",
            "certificates": [
                {"sha256": A, "spki_sha256": KEY_A},
                {"sha256": B, "spki_sha256": "2" * 64},
            ],
        },
    )
    registry = [
        {
            "id": "curl.mozilla_bundle",
            "kind": "bundled",
            "last_collection": {"artifact": r"M:\trustatlas\store\curl.json"},
        },
        {
            "id": "windows.root.machine",
            "kind": "os-store",
            "reader": ["collect_store.py", "--store", "Root"],
            "last_collection": {"artifact": r"M:\trustatlas\store\windows.machine.json"},
        },
        {
            "id": "windows.disallowed",
            "kind": "os-store",
            "reader": ["collect_store.py", "--store", "Disallowed"],
            "last_collection": {"artifact": r"M:\trustatlas\store\windows.machine.json"},
        },
        {
            "id": "mozilla.nss.certdata",
            "kind": "program-source",
            "last_collection": {"artifact": "mozilla.nss.json"},
        },
        {
            "id": "apple.security.framework",
            "kind": "os-store",
            "last_collection": {"collected": False},
        },
    ]
    write(
        tmp_path / "store" / "registry.status.json",
        {
            "artifact": "trustatlas.registry.status",
            "probed_at": "2026-11-14T01:00:00Z",
            "stores": registry,
        },
    )
    return tmp_path


def test_every_answer_names_the_artifacts_and_their_retrieved_at(data: Path) -> None:
    atlas = Atlas(data)
    answer = atlas.anchor(cert_sha256=A)
    assert {a.store: a.state for a in answer.answers} == {
        "curl.mozilla_bundle": "present",
        "windows.root.machine": "present",
        "windows.disallowed": "absent",
        "mozilla.nss.certdata": "absent",
        "apple.security.framework": "unread",
    }
    for a in answer.answers:
        if a.state == "unread":
            assert a.evidence is None
            assert a.reason
            continue
        assert a.evidence is not None, a
        assert a.evidence.retrieved_at, a
        assert (
            a.evidence.sha256 == hashlib.sha256((data / a.evidence.path).read_bytes()).hexdigest()
        )
    curl = next(a for a in answer.answers if a.store == "curl.mozilla_bundle")
    assert curl.evidence is not None
    assert curl.evidence.path == "store/curl.json"
    assert curl.evidence.retrieved_at == "2026-11-14T00:00:00Z"


def test_a_store_never_collected_is_listed_unread_and_never_left_out(data: Path) -> None:
    inventory = Atlas(data).inventory()
    assert [s.id for s in inventory.unread] == ["apple.security.framework"]
    assert inventory.unread[0].reason == "no artifact has been collected for this store"
    counts = {s.id: s.anchors for s in inventory.read}
    assert counts == {
        "curl.mozilla_bundle": 2,
        "windows.root.machine": 1,
        "windows.disallowed": 1,
        "mozilla.nss.certdata": 2,
    }, "rows sharing one artifact are counted per store, not per file"
    assert inventory.registry is not None
    assert inventory.registry.retrieved_at == "2026-11-14T01:00:00Z"


def test_a_listing_in_a_distrust_store_or_with_a_distrust_value_is_distrusted(data: Path) -> None:
    answer = Atlas(data).anchor(cert_sha256=C)
    states = {a.store: a.state for a in answer.answers}
    assert states["windows.disallowed"] == "distrusted"
    assert states["mozilla.nss.certdata"] == "present", "MUST_VERIFY_TRUST is not distrust"
    assert states["windows.root.machine"] == "absent"
    nss = Atlas(data).anchor(cert_sha256=B)
    assert {a.store: a.state for a in nss.answers}["mozilla.nss.certdata"] == "distrusted"


def test_a_key_query_says_unread_where_some_certificates_have_no_recorded_key(data: Path) -> None:
    answer = Atlas(data).anchor(spki_sha256=KEY_A)
    states = {a.store: a.state for a in answer.answers}
    assert states["curl.mozilla_bundle"] == "present"
    assert states["windows.root.machine"] == "present", (
        "the key is a property of the certificate, wherever it is"
    )
    assert states["mozilla.nss.certdata"] == "unread", (
        "C has no recorded key, so absence cannot be stated"
    )
    nss = next(a for a in answer.answers if a.store == "mozilla.nss.certdata")
    assert "1 of 2 certificates" in nss.reason
    assert Atlas(data).anchor(spki_sha256=KEY_C).where("present") == ()


def test_a_name_query_matches_the_strings_the_files_carry(data: Path) -> None:
    answer = Atlas(data).anchor(subject="example root a")
    assert {a.store for a in answer.present} == {"curl.mozilla_bundle", "windows.root.machine"}
    assert any("names are strings" in limit for limit in answer.limits)


def test_no_answer_uses_the_word_trusted_outside_the_sources_own_trust_values(data: Path) -> None:
    """`distrusted` is a state; the bare word `trusted` never is, and no reason the library writes uses it."""
    answer = Atlas(data).anchor(cert_sha256=B)
    for a in answer.answers:
        assert a.state in STATES
        assert not re.search(r"trusted", a.reason.lower()), a.reason


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({}, "exactly one"),
        ({"cert_sha256": A, "subject": "x"}, "exactly one"),
        ({"cert_sha256": "abc"}, "64 hex"),
        ({"spki_sha256": "z" * 64}, "64 hex"),
        ({"subject": "  "}, "must not be empty"),
    ],
)
def test_a_malformed_query_is_refused(data: Path, kwargs: dict[str, str], message: str) -> None:
    with pytest.raises(AtlasError, match=message):
        Atlas(data).anchor(**kwargs)


def test_without_a_registry_the_collector_artifacts_are_the_stores(tmp_path: Path) -> None:
    write(tmp_path / "store" / "curl.json", bundle("curl", {"sha256": A}))
    write(tmp_path / "store" / "curl-x-certifi.json", {"artifact": "trustatlas.join"})
    inventory = Atlas(tmp_path).inventory()
    assert [(s.id, s.read, s.anchors) for s in inventory.stores] == [("curl", True, 1)]
    assert inventory.registry is None


def test_a_missing_or_broken_artifact_is_unread_with_its_reason(tmp_path: Path) -> None:
    write(
        tmp_path / "store" / "registry.status.json",
        {
            "stores": [
                {"id": "gone", "last_collection": {"artifact": "gone.json"}},
                {"id": "bad", "last_collection": {"artifact": "bad.json"}},
            ]
        },
    )
    (tmp_path / "store" / "bad.json").write_text("{not json", encoding="utf-8")
    inventory = Atlas(tmp_path).inventory()
    reasons = {s.id: s.reason for s in inventory.unread}
    assert "not under" in reasons["gone"]
    assert "not readable JSON" in reasons["bad"]
    with pytest.raises(AtlasError, match="gone"):
        Atlas(tmp_path).store("gone")


def test_a_data_directory_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AtlasError, match="not a directory"):
        Atlas(tmp_path / "missing")
