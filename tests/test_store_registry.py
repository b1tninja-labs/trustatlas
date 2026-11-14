"""Pin what `tools/store_registry.py --probe` reports (row `ta.store_registry`).

The registry's value is that its table is trusted, so three behaviours are pinned here:

* a row whose reader is absent on this host, or which names no reader at all, stays in the status artifact and
  is reported unreachable with a reason. It is never dropped, because a missing row reads as "no such store";
* the two defects the row records as fixed stay fixed: rows name `collect_java.py` while the dispatcher once
  compared `collect_java`, which reported Java unreachable on a host with a JDK; and rows sharing one artifact
  reported that file's total for every hive, claiming `Disallowed` held 68 anchors when it holds none.

Hermetic: the PATH lookup, the platform name, `collect_java`'s keystore discovery and certifi's import are all
answered by the test, nothing is executed, and every artifact is read from and written to `tmp_path`.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import store_registry

NO_READER_ROW: dict[str, Any] = {
    "id": "test.no_reader",
    "kind": "os-store",
    "os": ("any",),
    "location": "nowhere in particular",
    "reader": [],
    "origin": "a row written before anyone wrote its reader",
    "artifact": None,
    "clients": (),
    "confidence": store_registry.GUESSED,
}


def fake_collect_java(keystore: Path | None) -> types.ModuleType:
    module = types.ModuleType("collect_java")

    def find_keystore(explicit: str | None) -> tuple[Path | None, list[str]]:
        return keystore, ["fake"]

    module.find_keystore = find_keystore  # type: ignore[attr-defined]
    return module


@pytest.fixture
def quiet_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Windows-named host with nothing on PATH, no JDK, and no certifi."""
    monkeypatch.setattr(store_registry.platform, "system", lambda: "Windows")
    monkeypatch.setattr(store_registry, "_which", lambda _name: None)
    monkeypatch.setitem(sys.modules, "collect_java", fake_collect_java(None))
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a: None if name == "certifi" else real_find_spec(name, *a),
    )

    def never(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the probe must not execute anything when no reader is on PATH")

    monkeypatch.setattr(store_registry.subprocess, "run", never)


def run_probe(monkeypatch: pytest.MonkeyPatch, data: Path) -> dict[str, Any]:
    monkeypatch.setattr(sys, "argv", ["store_registry.py", "--probe", "--data", str(data)])
    assert store_registry.main() == 0
    return json.loads((data / "store" / "registry.status.json").read_text(encoding="utf-8"))


@pytest.mark.usefixtures("quiet_host")
def test_a_row_without_a_reader_is_reported_unreachable_not_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(store_registry, "REGISTRY", (*store_registry.REGISTRY, NO_READER_ROW))
    doc = run_probe(monkeypatch, tmp_path)

    # Every row of the table is in the artifact, once, in table order: absence of a reader is not absence of a row.
    ids = [row["id"] for row in doc["stores"]]
    assert ids == [entry["id"] for entry in store_registry.REGISTRY]
    assert doc["provenance"]["registry_rows"] == len(store_registry.REGISTRY)
    rows = {row["id"]: row for row in doc["stores"]}

    # A row naming no reader says so, rather than "'' not on PATH".
    assert rows["test.no_reader"]["host"] == {"reachable": False, "why": "row names no reader"}
    assert rows["test.no_reader"]["last_collection"]["collected"] is False

    # A reader that is not on PATH is unreachable with the reader named, and the row keeps all its fields.
    openssl = rows["openssl.default"]
    assert openssl["host"] == {"reachable": False, "why": "'openssl' not on PATH"}
    for field in ("location", "origin", "clients"):
        assert openssl[field], field
    assert openssl["last_collection"] == {
        "collected": False,
        "reason": "registry row names no artifact yet",
    }

    # A row for another OS is unreachable by placement, not by absence.
    apple = rows["apple.security.framework"]["host"]
    assert apple["reachable"] is False
    assert "this host is windows" in apple["why"]

    # The JDK branch answers "no JDK", certifi answers "not installed": each says why, none is dropped.
    assert rows["java.cacerts"]["host"]["reachable"] is False
    assert "no JDK" in rows["java.cacerts"]["host"]["why"]
    assert rows["certifi"]["host"] == {"reachable": False, "why": "certifi not installed here"}

    # Every unreachable row carries a reason; none is silently blank.
    for row in doc["stores"]:
        if not row["host"].get("reachable"):
            assert row["host"].get("why"), row["id"]


@pytest.mark.parametrize("head", ["collect_java.py", "collect_java"])
def test_a_reader_named_with_its_suffix_dispatches_by_stem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, head: str
) -> None:
    keystore = tmp_path / "cacerts"
    keystore.write_bytes(b"\xfe\xed\xfe\xed" + b"\x00" * 60)
    monkeypatch.setattr(store_registry.platform, "system", lambda: "Windows")
    monkeypatch.setitem(sys.modules, "collect_java", fake_collect_java(keystore))

    def no_path_lookup(name: str) -> None:
        raise AssertionError(
            f"{name!r} was looked up on PATH instead of dispatched to collect_java"
        )

    monkeypatch.setattr(store_registry, "_which", no_path_lookup)
    java = next(e for e in store_registry.REGISTRY if e["id"] == "java.cacerts")
    assert java["reader"][0] == "collect_java.py"  # the form the table actually uses

    seen = store_registry.presence({**java, "reader": [head]})
    assert seen["reachable"] is True
    assert seen["path"] == str(keystore)
    assert seen["octets"] == 64


@pytest.mark.usefixtures("quiet_host")
def test_rows_sharing_an_artifact_report_their_own_store_not_the_file_total(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = tmp_path / "store"
    store.mkdir()
    (store / "windows.machine.json").write_text(
        json.dumps(
            {
                "artifact": "trustatlas.store.collect",
                "retrieved_at": "2026-11-06T00:00:00+00:00",
                "program": "Windows/schannel machine store",
                "counts": {
                    "anchors": 5,
                    "distinct_certificates": 4,
                    "per_store": {"Root": 3, "AuthRoot": 2, "Disallowed": 0},
                },
            }
        ),
        encoding="utf-8",
    )
    doc = run_probe(monkeypatch, tmp_path)
    rows = {row["id"]: row["last_collection"] for row in doc["stores"]}

    sharing = {
        e["id"] for e in store_registry.REGISTRY if e.get("artifact") == "windows.machine.json"
    }
    assert sharing == {"windows.root.machine", "windows.authroot.machine", "windows.disallowed"}
    assert rows["windows.root.machine"]["store"] == "Root"
    assert rows["windows.root.machine"]["anchors"] == 3
    assert rows["windows.authroot.machine"]["anchors"] == 2
    # Zero is a count, not a missing value: Disallowed must not fall through to the file's total.
    assert rows["windows.disallowed"]["anchors"] == 0
    for row_id in sharing:
        assert rows[row_id]["collected"] is True
        assert rows[row_id]["anchors"] != 4


def test_an_artifact_without_per_store_counts_reports_its_total(tmp_path: Path) -> None:
    store = tmp_path / "store"
    store.mkdir()
    (store / "curl.json").write_text(
        json.dumps({"retrieved_at": "x", "counts": {"anchors": 118}}), encoding="utf-8"
    )
    state = store_registry.artifact_state(str(tmp_path), "curl.json")
    assert state["collected"] is True
    assert state["anchors"] == 118
    missing = store_registry.artifact_state(str(tmp_path), "absent.json")
    assert missing["collected"] is False
    assert "does not exist" in missing["reason"]
