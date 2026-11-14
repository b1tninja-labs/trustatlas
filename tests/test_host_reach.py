"""Pin `tools/host_reach.py` (rows `ta.host_chain_in`, `ta.host_reach`, `ta.host_reach_twin`, `ta.host_reach_hostile`).

Hermetic: certificates are built here with the dev-only `cryptography` package, artifacts are written into
`tmp_path`, and nothing touches the network or `M:\\trustatlas`. The tool itself stays stdlib-only; it asks
asn1core's reader for SPKI digests as a subprocess, and the tests that need that reader find it exactly the way
the tool does (`--asn1core`, `$ASN1CORE_ROOT`, then the sibling checkout) and skip, saying so, when it is absent.
The refusal tests need no reader at all: they hand the tool a stand-in that records being called, and assert it
never was.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import host_reach
import pytest

pytest.importorskip("cryptography", reason="the dev extra builds test certificates")

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

READER = host_reach.find_asn1core(None)
needs_reader = pytest.mark.skipif(
    READER is None,
    reason="asn1core/tools/collect_anchors.py is not beside this checkout and ASN1CORE_ROOT is unset; "
    "the join cannot be exercised without asn1core's reader",
)

WHEN = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def cert(
    subject: str,
    subject_key: ec.EllipticCurvePrivateKey,
    issuer: str | None = None,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
    serial: int = 1,
) -> bytes:
    """DER of a certificate for `subject_key`, signed by `issuer_key` (self-signed when none)."""
    name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, issuer or subject)])
    built = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(WHEN)
        .not_valid_after(WHEN + datetime.timedelta(days=365))
        .sign(issuer_key or subject_key, hashes.SHA256())
    )
    return built.public_bytes(serialization.Encoding.DER)


def spki(der: bytes) -> str:
    """The SPKI digest computed independently of asn1core, so the tool's reader is checked, not echoed."""
    public = cx509.load_der_x509_certificate(der).public_key()
    return hashlib.sha256(
        public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def presented(position: int, der: bytes, spki_sha256: str | None = "auto") -> dict[str, Any]:
    return {
        "position": position,
        "der_b64": base64.b64encode(der).decode("ascii"),
        "sha256": hashlib.sha256(der).hexdigest(),
        "spki_sha256": spki(der) if spki_sha256 == "auto" else spki_sha256,
    }


def captured(host: str, certificates: list[dict[str, Any]], port: int = 443) -> dict[str, Any]:
    return {
        "host": host,
        "port": port,
        "status": "captured",
        "peer_asserted": True,
        "tls_verified": False,
        "path_id": "tls-observe",
        "vantage": "local/test",
        "started_utc": "2026-11-14T00:00:00Z",
        "duration_ms": 3,
        "peer_address": "192.0.2.10",
        "tls_version": "TLSv1.3",
        "chain_length": len(certificates),
        "certificates": certificates,
    }


def other(host: str, status: str, **extra: Any) -> dict[str, Any]:
    row = {
        "host": host,
        "port": 443,
        "status": status,
        "peer_asserted": True,
        "tls_verified": False,
        "path_id": "tls-observe",
        "vantage": "local/test",
        "started_utc": "2026-11-14T00:00:00Z",
        "duration_ms": 1,
        "detail": f"{status} in a test",
    }
    row.update(extra)
    return row


def document(*rows: dict[str, Any], schema: str = host_reach.INPUT_SCHEMA) -> dict[str, Any]:
    return {"schema": schema, "limits": ["peer-asserted, test fixture"], "rows": list(rows)}


def write_program(data: Path, program: str, ders: list[bytes]) -> None:
    """A `<program>.spki.json` in the shape `check_spki_artifact.py` writes, carrying only the join fields."""
    rows = [{"sha256": hashlib.sha256(d).hexdigest(), "spki_sha256": spki(d)} for d in ders]
    doc = {
        "artifact": "trustatlas.spki_identity",
        "version": 1,
        "program": program,
        "certificates": rows,
    }
    (data / f"{program}{host_reach.SPKI_SUFFIX}").write_text(json.dumps(doc), encoding="utf-8")


def run(
    tmp_path: Path, doc: dict[str, Any] | bytes, reader: Path | None = None
) -> tuple[int, Path, Path]:
    """Write the input, run `main`, return (exit code, output path, data directory)."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    source = tmp_path / "host-chain.json"
    source.write_bytes(doc if isinstance(doc, bytes) else json.dumps(doc).encode("utf-8"))
    out = data / "host" / "host-reach.json"
    script = reader or READER
    assert script is not None
    code = host_reach.main(
        ["--input", str(source), "--data", str(data), "--out", str(out), "--asn1core", str(script)]
    )
    return code, out, data


@pytest.fixture
def stand_in(tmp_path: Path) -> Iterator[Path]:
    """A `collect_anchors.py` that records being run and fails, so a refusal test proves no join started."""
    folder = tmp_path / "fake_asn1core" / "tools"
    folder.mkdir(parents=True)
    script = folder / "collect_anchors.py"
    marker = tmp_path / "reader_was_run"
    script.write_text(
        f"import pathlib, sys\npathlib.Path({str(marker)!r}).write_text('ran')\nsys.exit(9)\n",
        encoding="utf-8",
    )
    yield script
    assert not marker.exists(), "the reader ran on a document that should have been refused first"


def files_under(path: Path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


def strings(node: object, keys: set[str]) -> Iterator[str]:
    """Every string value in a JSON tree, collecting the keys separately."""
    if isinstance(node, dict):
        for k, v in node.items():
            keys.add(k)
            yield from strings(v, keys)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v, keys)
    elif isinstance(node, str):
        yield node


# ------------------------------------------------------------------------------------------- ta.host_chain_in


def test_a_chain_without_retained_raw_is_refused_and_nothing_is_written(
    tmp_path: Path, stand_in: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    der = cert("leaf.example.test", key())
    no_raw = presented(0, der)
    del no_raw["der_b64"]
    cases = {
        "captured row without der_b64": document(captured("a.example.test", [no_raw])),
        "captured row with no certificates": document(captured("a.example.test", [])),
        "short schema name": document(
            captured("a.example.test", [presented(0, der)]), schema="host-chain/1"
        ),
        "a later schema": document(
            captured("a.example.test", [presented(0, der)]), schema="certledger.host-chain/2"
        ),
        "sha256 not of the retained bytes": document(
            captured("a.example.test", [{**presented(0, der), "sha256": "0" * 64}])
        ),
        "a field the contract does not have": document(
            {**captured("a.example.test", [presented(0, der)]), "trusted": True}
        ),
    }
    for why, doc in cases.items():
        code, out, data = run(tmp_path, doc, reader=stand_in)
        assert code == 1, why
        assert not out.exists(), why
        assert files_under(data) == [], f"{why}: wrote {files_under(data)}"
        assert "REFUSED" in capsys.readouterr().err, why


# ---------------------------------------------------------------------------------------------- ta.host_reach

# The output's own field names. The scan below covers every key and every value; this set is pinned so a new
# field has to be added here deliberately, where its name is read against the rule.
PINNED_FIELDS = {
    "schema",
    "input",
    "sha256",
    "rows",
    "reader",
    "limits",
    "programs",
    "state",
    "artifact",
    "artifact_sha256",
    "keys",
    "why",
    "hosts",
    "host",
    "port",
    "status",
    "peer_asserted",
    "tls_verified",
    "positions",
    "position",
    "spki_sha256",
    "listed_certificates",
    "chain_length",
}


@needs_reader
def test_a_chain_is_never_reported_as_trusted_only_as_containing_a_listed_key(
    tmp_path: Path,
) -> None:
    root_key, other_root_key = key(), key()
    root = cert("Example Root", root_key)
    other_root = cert("Other Root", other_root_key)
    leaf = cert("www.example.test", key(), "Example Root", root_key, serial=2)
    data = tmp_path / "data"
    data.mkdir()
    write_program(data, "curl", [root])
    write_program(data, "mozilla.nss", [other_root])
    doc = document(
        captured("www.example.test", [presented(0, leaf), presented(1, root)]),
        other("down.example.test", "timeout"),
    )
    code, out, _ = run(tmp_path, doc)
    assert code == 0
    first = out.read_bytes()
    reach = json.loads(first)

    assert reach["schema"] == "host-reach/1"
    assert "identity join only: no path validation" in reach["limits"]
    host = reach["hosts"][0]
    assert (host["peer_asserted"], host["tls_verified"]) == (True, False)
    leaf_at, root_at = host["positions"]
    assert leaf_at["programs"]["curl"] == "absent"
    assert root_at["programs"]["curl"] == "present"
    assert root_at["programs"]["mozilla.nss"] == "absent"
    # A program with no key artifact is unread, never absent.
    assert root_at["programs"]["windows.machine"] == "unread"
    assert reach["programs"]["windows.machine"]["state"] == "unread"
    assert root_at["spki_sha256"] == spki(root)
    assert reach["hosts"][1]["status"] == "timeout"
    assert reach["hosts"][1]["positions"] == []

    # No wall clock: the same inputs give the same bytes, and nothing in them looks like a timestamp.
    assert run(tmp_path, doc)[1].read_bytes() == first
    assert not re.search(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", first)

    keys: set[str] = set()
    values = list(strings(reach, keys))
    host_keys = {k for k in keys if k not in PINNED_FIELDS}
    # Program names are keys too; they come from the artifacts, so they are scanned like values.
    assert host_keys <= set(reach["programs"]), (
        f"unpinned output fields: {host_keys - set(reach['programs'])}"
    )
    for text in [*values, *keys]:
        assert "trust" not in text.lower(), f"output says {text!r}"


# ----------------------------------------------------------------------------------------- ta.host_reach_twin


@needs_reader
def test_cross_signed_twin_matches_on_key_not_certificate(tmp_path: Path) -> None:
    shared, old_root_key = key(), key()
    self_signed = cert("New Root", shared)
    cross_signed = cert("New Root", shared, "Old Root", old_root_key, serial=7)
    leaf = cert("pkg.example.test", key(), "New Root", shared, serial=3)
    assert self_signed != cross_signed
    assert spki(self_signed) == spki(cross_signed)
    data = tmp_path / "data"
    data.mkdir()
    write_program(data, "curl", [self_signed])
    code, out, _ = run(
        tmp_path,
        document(captured("pkg.example.test", [presented(0, leaf), presented(1, cross_signed)])),
    )
    assert code == 0
    twin = json.loads(out.read_bytes())["hosts"][0]["positions"][1]
    assert twin["programs"]["curl"] == "present"
    assert twin["sha256"] == hashlib.sha256(cross_signed).hexdigest()
    assert twin["listed_certificates"]["curl"] == [hashlib.sha256(self_signed).hexdigest()]
    assert twin["spki_sha256"] == spki(self_signed)


# -------------------------------------------------------------------------------------- ta.host_reach_hostile


@needs_reader
def test_hostile_chains_end_as_limits_not_crashes(
    tmp_path: Path, stand_in: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    der = cert("leaf.example.test", key())
    pem_lower = (
        "-----begin certificate-----\n"
        + base64.encodebytes(der).decode("ascii")
        + "-----end certificate-----\n"
    )
    huge = b"\x30" * (5 * 1024 * 1024)

    # Refusals: the whole document is turned away, nothing is written and the reader never runs.
    refusals = {
        "200 certificates": document(
            captured("many.example.test", [presented(i, der) for i in range(200)])
        ),
        "a 5 MB certificate": document(
            captured(
                "big.example.test",
                [
                    {
                        "position": 0,
                        "der_b64": base64.b64encode(huge).decode("ascii"),
                        "sha256": hashlib.sha256(huge).hexdigest(),
                        "spki_sha256": None,
                    }
                ],
            )
        ),
        "a lowercase PEM boundary in place of DER": document(
            captured(
                "pem.example.test",
                [{"position": 0, "der_b64": pem_lower, "sha256": "0" * 64, "spki_sha256": None}],
            )
        ),
    }
    for why, doc in refusals.items():
        code, out, data = run(tmp_path, doc, reader=stand_in)
        assert code == 1, why
        assert not out.exists(), why
        assert files_under(data) == [], why
        assert "REFUSED" in capsys.readouterr().err, why
    for why, raw in {"not JSON": b"\xff\xfe{", "deep nesting": b"[" * 100_000}.items():
        code, out, _ = run(tmp_path, raw, reader=stand_in)
        assert code == 1, why
        assert not out.exists(), why

    # Limits: written, and the hostile part is a recorded limit rather than a guess.
    armoured = pem_lower.encode("ascii")
    hostile_name = "evil/../x@pkg.example.test"
    code, out, data = run(
        tmp_path,
        document(
            captured(hostile_name, [presented(0, der)]),
            captured("pem.example.test", [presented(0, armoured, spki_sha256=None)]),
            other(
                "many.example.test",
                "limit",
                chain_length=200,
                peer_address="192.0.2.11",
                tls_version="TLSv1.3",
            ),
        ),
    )
    assert code == 0
    assert files_under(data) == ["host", str(Path("host") / "host-reach.json")]
    hosts = json.loads(out.read_bytes())["hosts"]
    named, pem, many = hosts
    assert named["host"] == hostile_name
    assert any("not a DNS name" in limit for limit in named["limits"])
    assert pem["positions"][0]["spki_sha256"] is None
    assert set(pem["positions"][0]["programs"].values()) == {"unread"}
    assert any("no SPKI digest" in limit for limit in pem["limits"])
    assert many["status"] == "limit"
    assert many["chain_length"] == 200
    assert many["positions"] == []
