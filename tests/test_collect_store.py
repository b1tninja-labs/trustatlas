"""Pin that `tools/collect_store.py`'s counts re-derive from its own anchor list (row `ta.collect_store`).

The row records 68 `Root` / 52 `AuthRoot` / 0 `Disallowed` from one machine. Those numbers are only evidence if
the `counts` block of the artifact is a function of the `anchors` block beside it, so that anyone holding the
file can recompute them without the machine. The test feeds the tool canned provider output through a fake
`subprocess.run`, so it runs on any OS, and then recomputes every count from the written anchor list.

Hermetic: PowerShell is never started, the placement check is answered by the test, and the artifact lands in
`tmp_path`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import collect_store

SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CODE_SIGNING = "1.3.6.1.5.5.7.3.3"


def row(store: str, digest: str, subject: str, eku: list[str] | None) -> dict[str, Any]:
    """One object shaped like the PowerShell script's output; the digest is upper-case, as Windows prints it."""
    return {
        "store": store,
        "subject": subject,
        "friendly": "",
        "not_before": "2000-01-01T00:00:00Z",
        "not_after": "2040-01-01T00:00:00Z",
        "sha256": digest.upper(),
        "sha1": digest[:40].upper(),
        "self_signed": True,
        "eku": eku,
        "der_base64": None,
    }


D1, D2, D3, D4 = ("a1" * 32, "b2" * 32, "c3" * 32, "d4" * 32)

# Root holds three, AuthRoot two, and D2 is in both: 5 anchors, 4 distinct certificates, 1 shared.
# Disallowed is requested and empty, which the artifact must record as 0 rather than omit.
CANNED = [
    row("Root", D1, "CN=Root One", [SERVER_AUTH, "Server Authentication"]),
    row(
        "Root",
        D2,
        "CN=Shared Two",
        [SERVER_AUTH, "Server Authentication", CODE_SIGNING, "Code Signing"],
    ),
    row("Root", D3, "CN=Root Three", []),
    row("AuthRoot", D2, "CN=Shared Two", None),
    row("AuthRoot", D4, "CN=AuthRoot Four", [CODE_SIGNING, "Code Signing"]),
]


class FakeProvider:
    """Stands in for `powershell.exe`: records what it was asked and prints the canned JSON."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append({"argv": argv, "env": kwargs.get("env") or {}})
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(self.rows), stderr="")


def run_main(
    monkeypatch: pytest.MonkeyPatch, data: Path, *, windows: bool
) -> tuple[int, FakeProvider]:
    fake = FakeProvider(CANNED)
    monkeypatch.setattr(collect_store.subprocess, "run", fake)
    monkeypatch.setattr(collect_store, "on_windows", lambda: windows)
    monkeypatch.setattr(sys, "argv", ["collect_store.py", "--data", str(data)])
    return collect_store.main(), fake


def rederive(doc: dict[str, Any]) -> dict[str, Any]:
    """Every count, from the anchor list alone. Nothing here reads `doc["counts"]`."""
    anchors = doc["anchors"]
    stores_by_digest: dict[str, set[str]] = {}
    for anchor in anchors:
        stores_by_digest.setdefault(anchor["sha256"], set()).add(anchor["store"])
    per_store = dict.fromkeys(doc["provenance"]["stores"], 0)
    per_store.update(Counter(anchor["store"] for anchor in anchors))
    return {
        "anchors": len(anchors),
        "distinct_certificates": len(stores_by_digest),
        "per_store": per_store,
        "in_more_than_one_store": sum(1 for s in stores_by_digest.values() if len(s) > 1),
        "with_server_auth_eku": sum(1 for a in anchors if SERVER_AUTH in a["eku"]),
        "with_no_eku_extension": sum(1 for a in anchors if not a["eku"]),
    }


def test_store_counts_rederive_from_the_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, fake = run_main(monkeypatch, tmp_path, windows=True)
    assert code == 0

    # The provider was asked once, for the default stores of the machine hive, through the environment.
    assert len(fake.calls) == 1
    assert fake.calls[0]["argv"][0] == "powershell.exe"
    assert fake.calls[0]["env"]["TA_STORES"] == "Root,AuthRoot,Disallowed"
    assert fake.calls[0]["env"]["TA_LOCATION"] == "LocalMachine"
    assert "TA_WITH_DER" not in fake.calls[0]["env"]

    written = list((tmp_path / "store").iterdir())
    assert [p.name for p in written] == ["windows.machine.json"]
    doc = json.loads(written[0].read_text(encoding="utf-8"))

    # The counts are a function of the anchor list...
    assert doc["counts"] == rederive(doc)
    # ...and that function gives the numbers the canned store actually holds.
    assert doc["counts"] == {
        "anchors": 5,
        "distinct_certificates": 4,
        "per_store": {"Root": 3, "AuthRoot": 2, "Disallowed": 0},
        "in_more_than_one_store": 1,
        "with_server_auth_eku": 2,
        "with_no_eku_extension": 2,
    }
    # Digests are recorded lower-case, so the shared certificate is one certificate and not two spellings.
    assert {a["sha256"] for a in doc["anchors"]} == {D1, D2, D3, D4}
    # Hashes and counts only: no DER unless asked.
    assert doc["provenance"]["certificates_written"] is False
    assert all("der_octets" not in a for a in doc["anchors"])
    assert not (tmp_path / "store" / "der").exists()


def test_a_non_windows_host_exits_3_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, fake = run_main(monkeypatch, tmp_path, windows=False)
    assert code == 3
    assert fake.calls == []
    assert not (tmp_path / "store").exists()
    assert "host-resident probe" in capsys.readouterr().err


def test_a_provider_that_returns_nothing_claims_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeProvider([])
    monkeypatch.setattr(collect_store.subprocess, "run", fake)
    monkeypatch.setattr(collect_store, "on_windows", lambda: True)
    monkeypatch.setattr(sys, "argv", ["collect_store.py", "--data", str(tmp_path)])
    assert collect_store.main() == 1
    assert not (tmp_path / "store").exists()
