"""Pin what `tools/collect_java.py` may claim about a JDK trust store, without a JDK.

`keytool -list -rfc` is Java's own reader, so the test stubs *its output* rather than any keystore format:
the stub prints what JDK 26's keytool prints (an `Alias name:` line, the `Creation date:` and `Entry type:`
boilerplate the first real run mistook for names, the PEM block and the asterisk rules between entries) and
the collector is run end to end against a keystore path in a temporary directory. Nothing here opens a
socket, needs `M:\\trustatlas` or runs a JVM.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import collect_java  # the script under test

BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"


def synthetic_der(marker: bytes) -> bytes:
    """A byte string shaped like a DER SEQUENCE, never decoded: only its SHA-256 matters here."""
    body = bytes([0x30, 0x03, 0x02, 0x01, 0x01]) + marker + b"\x00" * (64 - len(marker))
    return bytes([0x30, len(body)]) + body


def pem_for(marker: bytes) -> str:
    b64 = base64.b64encode(synthetic_der(marker)).decode("ascii")
    return "\n".join([BEGIN, *(b64[i : i + 64] for i in range(0, len(b64), 64)), END])


def keytool_rfc(entries: list[tuple[str, bytes]]) -> str:
    """What `keytool -list -rfc` prints on JDK 26 for trustedCertEntry rows, reproduced as text."""
    out = [
        "Keystore type: PKCS12",
        "Keystore provider: SUN",
        "",
        f"Your keystore contains {len(entries)} entries",
        "",
    ]
    for alias, marker in entries:
        out += [
            f"Alias name: {alias}",
            "Creation date: Nov 7, 2026",
            "Entry type: trustedCertEntry",
            "",
            pem_for(marker),
            "",
            "",
            "*******************************************",
            "*******************************************",
            "",
            "",
        ]
    return "\n".join(out)


def test_aliases_are_captured_and_subjects_stay_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ta.readers_remaining`: keytool's alias is recorded as `alias`, and `subject` is never filled.

    An alias is a nickname the keystore chose. Recording it as a subject would name a certificate something
    it does not say, so even an alias that *looks* like a distinguished name stays an alias, and the date
    and entry-type boilerplate between the alias and the block names nothing.
    """
    jdk = tmp_path / "jdk"
    keystore = jdk / "lib" / "security" / "cacerts"
    keystore.parent.mkdir(parents=True)
    keystore.write_bytes(b"not a keystore: keytool is stubbed, and this file is only hashed")
    (jdk / "bin").mkdir()
    (jdk / "bin" / "keytool").write_bytes(b"")

    entries = [
        ("actalisauthenticationrootca [jdk]", b"A"),
        ("CN=Looks Like A Subject, O=Example", b"B"),
        ("digicertglobalrootg2 [jdk]", b"C"),
    ]
    printed = keytool_rfc(entries)
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=printed.encode("ascii"), stderr=b"")

    monkeypatch.setattr(collect_java.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collect_java.py",
            "--data",
            str(tmp_path / "data"),
            "--keystore",
            str(keystore),
        ],
    )
    assert collect_java.main() == 0

    # Only keytool ran (no java beside it), as `-list -rfc` against the keystore that was found.
    assert len(calls) == 1
    assert calls[0][:4] == [str(jdk / "bin" / "keytool"), "-list", "-rfc", "-keystore"]
    assert calls[0][4] == str(keystore)

    doc = json.loads((tmp_path / "data" / "store" / "java.cacerts.json").read_text("utf-8"))
    rows = {r["sha256"]: r for r in doc["certificates"]}
    for alias, marker in entries:
        row = rows[hashlib.sha256(synthetic_der(marker)).hexdigest()]
        assert row["alias"] == alias
        assert row["subject"] is None
        assert row["store"] == "java.cacerts"

    counts = doc["counts"]
    assert counts["pem_blocks"] == counts["distinct_certificates"] == 3
    assert counts["named"] == 3
    assert counts["subject_named"] == 0
    assert counts["malformed_blocks"] == counts["duplicate_blocks"] == 0

    provenance = doc["provenance"]
    assert provenance["keystore_sha256"] == hashlib.sha256(keystore.read_bytes()).hexdigest()
    assert provenance["jdk_version"] == "no java beside keytool"
    # The storepass is the JDK's published default, but the recorded command still never carries it.
    assert "changeit" not in provenance["command"]
    assert "<storepass>" in provenance["command"]
    assert "not a subject" in provenance["note"]


STOREPASS = "n0t-the-default-Storepass"


def run_collector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    printed: bytes,
    *extra: str,
) -> tuple[int, Path]:
    """Run `collect_java.main` against a stubbed keytool that prints `printed`; returns (exit, data dir)."""
    jdk = tmp_path / "jdk"
    keystore = jdk / "lib" / "security" / "cacerts"
    keystore.parent.mkdir(parents=True)
    keystore.write_bytes(b"not a keystore: keytool is stubbed, and this file is only hashed")
    (jdk / "bin").mkdir()
    (jdk / "bin" / "keytool").write_bytes(b"")

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        return subprocess.CompletedProcess(argv, 0, stdout=printed, stderr=b"")

    data = tmp_path / "data"
    monkeypatch.setattr(collect_java.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["collect_java.py", "--data", str(data), "--keystore", str(keystore), *extra],
    )
    return collect_java.main(), data


ENTRIES = [("actalisauthenticationrootca [jdk]", b"A"), ("digicertglobalrootg2 [jdk]", b"C")]


def test_raw_pem_is_retained_byte_for_byte_and_its_digest_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """keytool's stdout lands at `raw/java.cacerts.pem` unchanged (CRLF included), and the provenance names it."""
    printed = keytool_rfc(ENTRIES).replace("\n", "\r\n").encode("ascii")
    code, data = run_collector(tmp_path, monkeypatch, printed)
    assert code == 0

    raw = data / "raw" / "java.cacerts.pem"
    assert raw.read_bytes() == printed
    assert not list((data / "raw").glob("*.partial"))

    provenance = json.loads((data / "store" / "java.cacerts.json").read_text("utf-8"))["provenance"]
    assert provenance["raw"] == str(raw)
    assert provenance["raw_sha256"] == hashlib.sha256(printed).hexdigest()
    assert provenance["raw_octets"] == len(printed)
    assert provenance["raw_reindex"]["agrees"] is True
    assert provenance["raw_reindex"]["distinct_certificates"] == len(ENTRIES)


def test_reindexing_the_retained_file_reproduces_the_artifact_digest_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What `check_spki_artifact.py` will read is the same certificate set the artifact lists."""
    code, data = run_collector(tmp_path, monkeypatch, keytool_rfc(ENTRIES).encode("ascii"))
    assert code == 0

    doc = json.loads((data / "store" / "java.cacerts.json").read_text("utf-8"))
    listed = {row["sha256"] for row in doc["certificates"]}
    retained = (data / "raw" / "java.cacerts.pem").read_bytes()
    again, _ = collect_java.index_pem(
        collect_java.as_text(retained), program="java.cacerts", name_key="alias"
    )
    assert set(again) == listed
    assert listed == {hashlib.sha256(synthetic_der(m)).hexdigest() for _, m in ENTRIES}


def test_a_retained_file_that_does_not_reindex_refuses_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the bytes read back from disk lose a certificate, neither the raw file nor the artifact is kept."""
    printed = keytool_rfc(ENTRIES).encode("ascii")
    # The read-back drops the second entry: same file name, a different certificate set.
    truncated = keytool_rfc(ENTRIES[:1]).encode("ascii")
    monkeypatch.setattr(collect_java, "read_retained", lambda _path: truncated)
    code, data = run_collector(tmp_path, monkeypatch, printed)

    assert code != 0
    assert not (data / "store" / "java.cacerts.json").exists()
    assert not (data / "raw" / "java.cacerts.pem").exists()
    assert not [p for p in data.rglob("*") if p.is_file()]


def test_the_storepass_appears_in_no_written_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-default storepass reaches keytool's argv, and no byte of any written file carries it."""
    code, data = run_collector(
        tmp_path, monkeypatch, keytool_rfc(ENTRIES).encode("ascii"), "--storepass", STOREPASS
    )
    assert code == 0
    written = [p for p in data.rglob("*") if p.is_file()]
    assert {p.name for p in written} == {"java.cacerts.pem", "java.cacerts.json"}
    for path in written:
        assert STOREPASS.encode("ascii") not in path.read_bytes(), path


def test_output_that_echoes_the_storepass_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """keytool does not echo the storepass; if its output ever did, retaining it would publish it."""
    printed = (f"Keystore password: {STOREPASS}\n" + keytool_rfc(ENTRIES)).encode("ascii")
    code, data = run_collector(tmp_path, monkeypatch, printed, "--storepass", STOREPASS)
    assert code != 0
    assert not data.exists() or not [p for p in data.rglob("*") if p.is_file()]
