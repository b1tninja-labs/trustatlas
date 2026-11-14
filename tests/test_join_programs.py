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
import os
import subprocess
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
    assert first["provenance"]["trust_filter_not_applied"] == {}
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
    # B states no trust bits, so --b-trust is requested and not applied: B keeps all four, and the
    # artifact lists B under `trust_filter_not_applied`, not under `trust_filter`.
    assert both["provenance"]["trust_filter"] == {"a": "SERVER_AUTH"}
    assert set(both["provenance"]["trust_filter_not_applied"]) == {"b"}
    assert both["provenance"]["trust_filter_not_applied"]["b"]["requested"] == "SERVER_AUTH"
    assert both["provenance"]["totals_before_filter"] == {"a": 5, "b": 4}
    assert both["counts"] == only_a["counts"]
    assert both["shared"] == only_a["shared"]


def test_a_side_that_states_no_trust_bits_is_not_emptied_by_a_filter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_artifacts(tmp_path)
    doc = join(monkeypatch, tmp_path, tmp_path / "out" / "b.json", "--b-trust", "SERVER_AUTH")
    assert doc["counts"]["b"] == 4
    # Every count is the unfiltered join's: a filter that could not apply changes nothing but the record.
    assert doc["counts"] == {"a": 5, "b": 4, "shared": 3}


def test_an_unfilterable_side_is_recorded_as_not_filtered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_artifacts(tmp_path)
    doc = join(monkeypatch, tmp_path, tmp_path / "out" / "b.json", "--b-trust", "SERVER_AUTH")
    # A reader must not take "B is in no filter" for "B was filtered and all four passed": the request is
    # recorded beside the applied filters, with the reason it did not apply.
    assert doc["provenance"]["trust_filter"] == {}
    assert doc["provenance"]["trust_filter_not_applied"] == {
        "b": {
            "requested": "SERVER_AUTH",
            "reason": "the artifact states no trust bits for any anchor, so it is joined unfiltered",
        }
    }


def test_an_empty_trust_object_states_trust_and_is_filtered_out() -> None:
    # The real NSS artifact carries one anchor with `trust: {}`. It states trust (for nothing), so NSS stays
    # filterable as a whole and that anchor is dropped, as it was before the per-artifact rule.
    rows = [*A_ROWS, {"sha256": h("z1"), "subject": "CN=no bits", "store": "nss", "trust": {}}]
    assert join_programs.states_trust(rows) is True
    assert not join_programs.is_delegator(rows[-1], "SERVER_AUTH")


def test_a_mixed_artifact_is_refused_rather_than_filtered_per_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_artifacts(tmp_path)
    mixed = {
        "program": "mixed",
        "anchors": [*A_ROWS, {"sha256": h("silent"), "subject": "CN=silent"}],
    }
    (tmp_path / "store" / "a.json").write_text(json.dumps(mixed), encoding="utf-8")
    out = tmp_path / "out" / "mixed.json"
    argv = ["join_programs.py", "--data", str(tmp_path), "--a", "a.json", "--b", "b.json"]
    monkeypatch.setattr(sys, "argv", [*argv, "--out", str(out), "--a-trust", "SERVER_AUTH"])
    assert join_programs.main() == 2
    assert "mixed artifact" in capsys.readouterr().err
    assert not out.exists()
    # Unfiltered, the same artifact joins normally: the refusal is about the filter, not the rows.
    assert join_programs.states_trust([{"sha256": h("x")}]) is False


def test_cli_exit_code_is_mains_return(tmp_path: Path) -> None:
    write_artifacts(tmp_path)
    script = Path(join_programs.__file__)
    base = [sys.executable, str(script), "--data", str(tmp_path), "--b", "b.json"]

    def run(*extra: str) -> subprocess.CompletedProcess[str]:
        # argv is a list against the interpreter running this suite and the script it imported; no shell.
        return subprocess.run(  # noqa: S603
            [*base, *extra], capture_output=True, text=True, check=False
        )

    ok = run("--a", "a.json")
    assert ok.returncode == 0, ok.stderr
    assert run("--a", "absent.json").returncode == 1
    mixed = {"program": "mixed", "anchors": [*A_ROWS, {"sha256": h("silent")}]}
    (tmp_path / "store" / "mixed.json").write_text(json.dumps(mixed), encoding="utf-8")
    assert run("--a", "mixed.json", "--a-trust", "SERVER_AUTH").returncode == 2


def test_listing_survives_a_subject_the_console_cannot_encode(tmp_path: Path) -> None:
    # Windows pipes stdout under cp1252 by default, and NSS carries subjects (a Hungarian root's name) with
    # U+0151, which cp1252 has no byte for. The listing must still print, and the artifact must not change.
    write_artifacts(tmp_path)
    o_double_acute, rest = chr(0x151), "tan" + chr(0xFA) + "s" + chr(0xED) + "tv" + chr(0xE1) + "ny"
    subject = "CN=NetLock Arany (Class Gold) F" + o_double_acute + rest
    rows = [*A_ROWS, {"sha256": h("hu"), "subject": subject, "store": "nss", "trust": TLS}]
    a = {"program": "nss", "retrieved_at": "2026-11-07T00:00:00+00:00", "anchors": rows}
    (tmp_path / "store" / "a.json").write_text(json.dumps(a), encoding="utf-8")
    script = Path(join_programs.__file__)
    argv = [sys.executable, str(script), "--data", str(tmp_path), "--a", "a.json", "--b", "b.json"]

    def run(encoding: str, out: Path) -> subprocess.CompletedProcess[bytes]:
        env = {**os.environ, "PYTHONIOENCODING": encoding, "PYTHONUTF8": "0"}
        # argv is a list against the interpreter running this suite and the script it imported; no shell.
        return subprocess.run(  # noqa: S603
            [*argv, "--out", str(out)], capture_output=True, env=env, check=False
        )

    done = run("cp1252", tmp_path / "out" / "cp1252.json")
    assert done.returncode == 0, done.stderr.decode("cp1252", "replace")
    listing = done.stdout.decode("cp1252")
    # The unencodable character is escaped (backslash, "u0151"), not dropped and not replaced by "?", so the
    # name stays recoverable; the characters cp1252 does carry are printed as themselves.
    escaped = "F" + chr(0x5C) + "u0151" + rest + " [nss]"
    assert escaped in listing
    # The artifact is the same bytes whatever the console encoding: the escaping is the console's alone.
    assert run("utf-8", tmp_path / "out" / "utf8.json").returncode == 0
    written = (tmp_path / "out" / "cp1252.json").read_bytes()
    assert written == (tmp_path / "out" / "utf8.json").read_bytes()
    assert h("hu") in json.loads(written)["only_a"]
