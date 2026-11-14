"""Pin that `tools/join_programs.py` reproduces its counts from the artifacts alone (row `ta.join_programs`).

The row's numbers -- certifi x curl sharing 114, NSS-as-TLS x Java sharing 59 where unfiltered NSS gives 76 --
are only worth recording if running the join again over the same two artifacts yields them again, and if a
filtered join says it was filtered. Both are tested over synthetic artifacts written into `tmp_path`: an
NSS-shaped side that states trust bits per anchor and a bundle-shaped side that states none.

Hermetic: no network, no `M:\\trustatlas`, and the digests are of synthetic byte strings that nothing decodes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import join_programs


def h(marker: str) -> str:
    return hashlib.sha256(marker.encode("ascii")).hexdigest()


TLS = {"SERVER_AUTH": "CKT_NSS_TRUSTED_DELEGATOR"}
EMAIL_ONLY = {
    "SERVER_AUTH": "CKT_NSS_MUST_VERIFY_TRUST",
    "EMAIL_PROTECTION": "CKT_NSS_TRUSTED_DELEGATOR",
}

# Side A: five anchors, three trusted for TLS. Side B: four anchors with no trust bits at all.
#   shared unfiltered: s1, s2 (TLS), e1 (email-only)  -> 3
#   shared filtered to A's SERVER_AUTH:  s1, s2       -> 2
A_ROWS = [
    {"sha256": h("s1"), "subject": "CN=shared tls 1", "store": "nss", "trust": TLS},
    {"sha256": h("s2"), "subject": "CN=shared tls 2", "store": "nss", "trust": TLS},
    {"sha256": h("t3"), "subject": "CN=nss-only tls", "store": "nss", "trust": TLS},
    {"sha256": h("e1"), "subject": "CN=shared email", "store": "nss", "trust": EMAIL_ONLY},
    {"sha256": h("e2"), "subject": "CN=nss-only email", "store": "nss", "trust": EMAIL_ONLY},
]
B_ROWS = [{"sha256": h(m)} for m in ("s1", "s2", "e1", "b1")]


def write_artifacts(data: Path) -> None:
    store = data / "store"
    store.mkdir(parents=True)
    a = {"program": "nss", "retrieved_at": "2026-11-07T00:00:00+00:00", "anchors": A_ROWS}
    b = {"program": "bundle", "retrieved_at": "2026-11-06T00:00:00+00:00", "certificates": B_ROWS}
    (store / "a.json").write_text(json.dumps(a), encoding="utf-8")
    (store / "b.json").write_text(json.dumps(b), encoding="utf-8")


def join(monkeypatch: pytest.MonkeyPatch, data: Path, out: Path, *extra: str) -> dict[str, Any]:
    argv = ["join_programs.py", "--data", str(data), "--a", "a.json", "--b", "b.json"]
    monkeypatch.setattr(sys, "argv", [*argv, "--out", str(out), *extra])
    assert join_programs.main() == 0
    return json.loads(out.read_text(encoding="utf-8"))


def test_join_reproduces_from_committed_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_artifacts(tmp_path)

    first = join(monkeypatch, tmp_path, tmp_path / "out" / "first.json")
    again = join(monkeypatch, tmp_path, tmp_path / "out" / "again.json")
    # Byte-for-byte the same document from the same two artifacts: nothing in a join depends on when it ran.
    assert (tmp_path / "out" / "first.json").read_bytes() == (
        tmp_path / "out" / "again.json"
    ).read_bytes()
    assert first == again

    assert first["counts"] == {"a": 5, "b": 4, "shared": 3}
    assert first["shared"] == sorted([h("s1"), h("s2"), h("e1")])
    assert first["only_a"] == sorted([h("t3"), h("e2")])
    assert first["only_b"] == [h("b1")]
    assert first["retrieved_at"] == "2026-11-07T00:00:00+00:00"
    assert first["provenance"]["key"] == "certificate SHA-256 of DER"
    # An unfiltered join records that it was unfiltered, not merely the absence of a key.
    assert first["provenance"]["trust_filter"] == {}
    assert first["provenance"]["totals_before_filter"] == {"a": 5, "b": 4}


def test_a_trust_filter_is_recorded_in_the_join_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_artifacts(tmp_path)
    # A drops its two email-only anchors; the artifact must say so, and keep the totals it filtered from,
    # because a stored join that silently filtered would lie later.
    only_a = join(
        monkeypatch, tmp_path, tmp_path / "out" / "tls-a.json", "--a-trust", "SERVER_AUTH"
    )
    assert only_a["provenance"]["trust_filter"] == {"a": "SERVER_AUTH"}
    assert only_a["provenance"]["totals_before_filter"] == {"a": 5, "b": 4}
    assert only_a["counts"] == {"a": 3, "b": 4, "shared": 2}
    assert only_a["shared"] == sorted([h("s1"), h("s2")])
    assert only_a["only_a"] == [h("t3")]
    assert only_a["only_b"] == sorted([h("e1"), h("b1")])

    both = join(
        monkeypatch,
        tmp_path,
        tmp_path / "out" / "tls-both.json",
        "--a-trust",
        "SERVER_AUTH",
        "--b-trust",
        "SERVER_AUTH",
    )
    assert both["provenance"]["trust_filter"] == {"a": "SERVER_AUTH", "b": "SERVER_AUTH"}
    assert both["provenance"]["totals_before_filter"] == {"a": 5, "b": 4}


@pytest.mark.xfail(
    strict=True,
    reason="is_delegator's docstring says an artifact that states no trust bits 'is never filtered by this', "
    "but a row with no `trust` key returns False, so --b-trust over a bundle empties side B",
)
def test_a_side_that_states_no_trust_bits_is_not_emptied_by_a_filter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_artifacts(tmp_path)
    doc = join(monkeypatch, tmp_path, tmp_path / "out" / "b.json", "--b-trust", "SERVER_AUTH")
    assert doc["counts"]["b"] == 4
