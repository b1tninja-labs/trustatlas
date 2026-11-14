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

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=printed, stderr="")

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
