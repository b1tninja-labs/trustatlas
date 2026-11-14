"""Pin that the key identity reaches trustatlas through an asn1core-produced artifact (row `ta.spki_key_identity`).

The join key a map of cross-signs needs is SPKI SHA-256: the digest of a certificate's subjectPublicKeyInfo, the
field RFC 5280 section 4.1.2.7 says carries the public key and the algorithm it is used with. Deriving it means
parsing DER, which `AGENTS.md` keeps out of this directory. So the identity must arrive as an artifact written
by `tools/check_spki_artifact.py`, which hands the retained raw payload to `asn1core/tools/collect_anchors.py`
as a subprocess, by path, and never imports it.

This test runs that real path end to end over a tiny store built in `tmp_path` -- three certificates, two of
which hold one key the way a root and its cross-signed twin do -- and checks every `spki_sha256` in the written
artifact against a digest computed here, independently, with `cryptography`. `cryptography` is a test-only
oracle: nothing under `tools/` imports it. When it or the sibling `asn1core` checkout is missing the test
skips and says which; it never passes without having compared a digest.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import check_spki_artifact


def make_certificates() -> list[tuple[bytes, str]]:
    """Three self-describing DER certificates and the SPKI SHA-256 each must report, computed here.

    `twin` is issued over `root`'s key under a different name, serial and issuer, so it is a different
    certificate holding the same key: the case certificate SHA-256 counts twice and SPKI SHA-256 collapses.
    """
    x509 = pytest.importorskip(
        "cryptography.x509",
        reason="cryptography is the independent oracle for SPKI SHA-256 and is not installed",
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    shared_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)

    def name(cn: str) -> Any:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def issue(subject: str, issuer: str, key: Any, signer: Any, serial: int) -> bytes:
        cert = (
            x509.CertificateBuilder()
            .subject_name(name(subject))
            .issuer_name(name(issuer))
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(signer, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    certs = [
        issue("ta test root", "ta test root", shared_key, shared_key, 1),
        issue("ta test root twin", "ta test bridge", shared_key, other_key, 2),
        issue("ta test other", "ta test other", other_key, other_key, 3),
    ]
    out: list[tuple[bytes, str]] = []
    for der in certs:
        # The oracle: cryptography's own DER encoding of the subjectPublicKeyInfo, hashed. For a certificate it
        # just wrote, that encoding is the stored field byte for byte, so agreement means asn1core hashed the
        # right span of the stored bytes and not a re-encoding of its own.
        spki = (
            x509.load_der_x509_certificate(der)
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        out.append((der, hashlib.sha256(spki).hexdigest()))
    return out


def armour(der: bytes) -> str:
    import base64

    body = base64.b64encode(der).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "\n".join(["-----BEGIN CERTIFICATE-----", *lines, "-----END CERTIFICATE-----", ""])


def test_key_identity_arrives_through_an_artifact(tmp_path: Path) -> None:
    certs = make_certificates()
    script, looked = check_spki_artifact.find_asn1core(None)
    if script is None:
        pytest.skip(
            "asn1core/tools/collect_anchors.py is not reachable from this checkout, so the key identity "
            f"cannot be derived here; looked at: {'; '.join(looked)}"
        )

    # A tiny store in the data directory's own layout: the retained raw payload, and the store artifact that
    # claims certificate digests only -- exactly what `collect_bundle.py` leaves behind.
    data = tmp_path / "data"
    (data / "raw").mkdir(parents=True)
    (data / "store").mkdir()
    (data / "raw" / "curl.pem").write_text("".join(armour(der) for der, _ in certs), "ascii")
    claimed = [{"sha256": hashlib.sha256(der).hexdigest()} for der, _ in certs]
    store = {
        "program": "curl",
        "retrieved_at": "2026-11-14T00:00:00+00:00",
        "certificates": claimed,
    }
    (data / "store" / "curl.json").write_text(json.dumps(store), encoding="utf-8")

    tool = Path(check_spki_artifact.__file__)
    argv = [sys.executable, str(tool), "curl", "--data", str(data), "--asn1core", str(script)]
    argv += ["--scratch", str(tmp_path / "scratch")]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    # argv is a list against the interpreter running this suite and a script resolved above; no shell.
    done = subprocess.run(  # noqa: S603
        argv, capture_output=True, text=True, encoding="utf-8", env=env, check=False, timeout=300
    )
    assert done.returncode == 0, done.stdout + done.stderr

    artifact = json.loads((data / "curl.spki.json").read_text(encoding="utf-8"))
    assert artifact["artifact"] == "trustatlas.spki_identity"
    # The artifact names the reader that parsed, and it is asn1core's, not anything under tools/ here.
    assert Path(artifact["provenance"]["reader"]).resolve() == script.resolve()
    assert (
        artifact["provenance"]["raw_sha256"]
        == hashlib.sha256((data / "raw" / "curl.pem").read_bytes()).hexdigest()
    )

    derived = {row["sha256"]: row["spki_sha256"] for row in artifact["certificates"]}
    expected = {hashlib.sha256(der).hexdigest(): spki for der, spki in certs}
    assert derived == expected

    # Three certificates, two keys: the twin collapses onto the root's key, and only at the key level.
    root, twin, other = (hashlib.sha256(der).hexdigest() for der, _ in certs)
    assert artifact["counts"]["certificates"] == 3
    assert artifact["counts"]["distinct_keys"] == 2
    assert artifact["counts"]["collapsed_by_key"] == 1
    sharing = artifact["keys_sharing_certificates"]
    assert {k: sorted(v) for k, v in sharing.items()} == {certs[0][1]: sorted([root, twin])}
    assert expected[other] not in sharing
    assert artifact["agreement_with_store_artifact"]["agrees"] is True
