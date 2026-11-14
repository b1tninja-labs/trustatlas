"""Join the chains certledger captured against the keys each root program lists, and say nothing more.

Rows `ta.host_chain_in`, `ta.host_reach`, `ta.host_reach_twin` and `ta.host_reach_hostile` in `ROADMAP.md`
section 2a. pkgtrust wants, per distribution hostname, the chain the host presented and which programs list a
key in it. Capturing that chain is `certledger`'s (`PORTFOLIO.md` section 9 item 15): this script never connects
to a host. It reads one `certledger.host-chain/1` document (`certledger/docs/host-chain-1.md`, whose code form
is `certledger.endpoint.validate`), and writes `host-reach/1`.

**What the join is.** For every certificate a host presented, the SHA-256 of its SubjectPublicKeyInfo is
compared with the keys listed in every `<program>.spki.json` in the data directory (written by
`check_spki_artifact.py`). Per position the answer is `present`, `absent` or `unread`:

* `present` - some certificate the program lists holds the same key. The listed certificate digests are
  reported beside the presented one, because they may differ.
* `absent` - the program's key artifact was read and no listed certificate holds that key.
* `unread` - there is no readable key artifact for that program, or asn1core could not frame this
  certificate. It is never reported as `absent`: a program nobody measured is not a program that lacks a key.

**What the join is not.** RFC 5280 section 6 paragraph 1 describes certification path processing as verifying
the binding between a subject name and a subject public key, limited by the constraints in the path and the
relying party's inputs. **None of section 6 is implemented here**: no signature is checked, no issuer is linked
to a subject, no validity period, constraint or policy is read, and no path is built. `present` therefore says
only that a presented key equals a key some program lists. It does not say the host chains to that program,
and the output never uses a word that would. Path validation is `pkix`'s, row `ta.reach`.

**Why the key and not the certificate.** RFC 4158 section 1.5.3 paragraph 1 describes cross-certification
between hierarchical PKIs as each Root CA issuing a certificate for the other's Root CA. Such a cross-signed
twin is a second certificate for the same key, so a join on certificate SHA-256 would miss it. This join keys
on the SPKI digest and reports both certificate digests (row `ta.host_reach_twin`). Building the paths that
RFC 4158 section 2 is about stays `pkix`'s too.

**No certificate is parsed in this file.** Each presented certificate's DER is handed to
`asn1core/tools/collect_anchors.py`, run as a subprocess by path (the pattern of `check_spki_artifact.py`), and
the SPKI digest that comes back is the join key. The digest certledger recorded is compared with it. When both
exist and differ the document is refused, because two readings of one set of bytes disagree. When either side
could not frame the certificate, the position is `unread` and the reason is a recorded limit.

**Refusal.** A document whose `schema` is not exactly `certledger.host-chain/1`, or that fails any check of
the contract (including a `captured` row without retained raw DER, a digest that does not match its bytes, more
than 32 certificates, or one over 1 MiB), is refused as a whole: exit 1, a reason on stderr, and nothing
written. A partial read is not supported, matching the contract's "What a consumer does" step 1.

**Recorded facts, carried through.** Every row's `peer_asserted` and `tls_verified` are copied as the row
stated them. A host name that is not a DNS name (one with `/` or `@`, say) is carried verbatim as a JSON
string, used only as a label and never as a path, and gets a per-host limit. Non-captured statuses (`refused`,
`timeout`, `no_tls`, `skipped`, `limit`) are carried as their own outcomes with no positions.

The output carries no wall clock, so the same input and artifacts give the same bytes.

Usage:
    python tools/host_reach.py --input host-chain.json --data M:\\trustatlas
    python tools/host_reach.py --input host-chain.json --data M:\\trustatlas --out reach.json
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeGuard

INPUT_SCHEMA = "certledger.host-chain/1"
OUTPUT_SCHEMA = "host-reach/1"
STATUSES = ("captured", "refused", "timeout", "no_tls", "skipped", "limit")

# The contract's caps (`certledger/endpoint.py` MAX_CERTIFICATES, MAX_CERTIFICATE_BYTES). A row past them is
# not a valid `captured` row, so it is refused here exactly as `validate` refuses it.
MAX_CERTIFICATES = 32
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_B64 = 4 * ((MAX_CERTIFICATE_BYTES + 2) // 3)
# Read no input larger than this at all; a document of honest rows at the caps stays well under it.
MAX_INPUT_BYTES = 256 * 1024 * 1024

# The programs a reader expects a column for. This is the set `check_spki_artifact.py` names, both those whose
# raw payload is retained and those it declines with a reason, so a program with no key artifact still appears
# as `unread` rather than vanishing. Any further `<program>.spki.json` found in the data directory is added.
DEFAULT_PROGRAMS = (
    "android.aosp",
    "certifi",
    "curl",
    "java.cacerts",
    "mozilla.nss",
    "node.bundled",
    "python.schannel",
    "windows.machine",
    "windows.user",
)
SPKI_SUFFIX = ".spki.json"
SPKI_ARTIFACT = ("trustatlas.spki_identity", 1)  # what `check_spki_artifact.py` writes

PRESENT, ABSENT, UNREAD = "present", "absent", "unread"
READER = "asn1core/tools/collect_anchors.py"

LIMITS = (
    "identity join only: no path validation",
    "RFC 5280 section 6 is not implemented: no signature, issuer link, validity, constraint or policy was "
    "checked and no path was built; present means a presented key equals a key the program lists, nothing more",
    "peer-asserted: positions are the certificates the peer presented, as certledger recorded them with "
    "verification off, in the order the peer sent them",
    "unread means the program has no readable key artifact here, or asn1core could not frame the "
    "certificate; it is never absent",
)

_DOC_KEYS = frozenset({"schema", "limits", "rows"})
_ROW_KEYS = frozenset(
    {
        "host",
        "port",
        "status",
        "peer_asserted",
        "tls_verified",
        "path_id",
        "vantage",
        "started_utc",
        "duration_ms",
        "detail",
        "peer_address",
        "tls_version",
        "chain_length",
        "certificates",
        "embedded_sct_log_ids",
    }
)
_CERTIFICATE_KEYS = frozenset({"position", "der_b64", "sha256", "spki_sha256"})
_HEX64 = re.compile(r"[0-9a-f]{64}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# One DNS label a reader can take at face value. A name with any other label is still carried, verbatim, with a
# limit. Checked label by label rather than with one nested-quantifier pattern, which backtracks on hostile input.
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class RefusalError(Exception):
    """The input cannot be joined; nothing may be written."""


def is_dns_name(host: str) -> bool:
    """A host name made only of DNS labels (a trailing dot allowed), at most 253 characters."""
    name = host.removesuffix(".")
    return 0 < len(name) <= 253 and all(_DNS_LABEL.fullmatch(label) for label in name.split("."))


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


# ---------------------------------------------------------------------------------------------------- input


def read_input(path: Path) -> dict[str, Any]:
    """The document, or `RefusalError`. Size is checked before a byte is read, and no shape of the file raises."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RefusalError(f"cannot read {path}: {type(exc).__name__}") from exc
    if size > MAX_INPUT_BYTES:
        raise RefusalError(f"{path} is {size} octets; at most {MAX_INPUT_BYTES} are read")
    try:
        doc = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RefusalError(f"{path} is not a JSON document: {type(exc).__name__}") from exc
    if not isinstance(doc, dict):
        raise RefusalError(f"{path} holds a {type(doc).__name__}, not an object")
    if doc.get("schema") != INPUT_SCHEMA:
        raise RefusalError(
            f"schema is {doc.get('schema')!r}, not {INPUT_SCHEMA!r}; another schema is refused"
        )
    return doc


def check_document(doc: Mapping[str, Any]) -> list[str]:
    """Every way `doc` breaks `certledger.host-chain/1`, short of the SPKI digest (which needs asn1core).

    A reimplementation of `certledger.endpoint.validate`, because the contract asks a consumer to run that or
    repeat every check, and this directory may not import certledger. The SPKI half is in `join`.
    """
    problems = [
        f"unknown document key {key!r}" for key in sorted(map(str, doc)) if key not in _DOC_KEYS
    ]
    limits = doc.get("limits")
    if not isinstance(limits, list) or not limits or not all(isinstance(x, str) for x in limits):
        problems.append("limits is not a non-empty list of strings")
    rows = doc.get("rows")
    if not isinstance(rows, list):
        return [*problems, "rows is not a list"]
    seen: dict[tuple[str, int], int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            problems.append(f"row {index}: not an object")
            continue
        where = f"row {index} ({row.get('host')!r})"
        problems.extend(_check_row(where, row))
        host, port = row.get("host"), row.get("port")
        if isinstance(host, str) and _is_int(port):
            key = (host.strip().lower().removesuffix("."), int(port))
            if key in seen:
                problems.append(f"{where}: second row for {key} (row {seen[key]})")
            else:
                seen[key] = index
    return problems


def _check_row(where: str, row: dict[str, Any]) -> list[str]:
    problems = [
        f"{where}: unknown key {key!r}" for key in sorted(map(str, row)) if key not in _ROW_KEYS
    ]
    status = row.get("status")
    if status not in STATUSES:
        problems.append(f"{where}: status {status!r} is not one of {STATUSES}")
        status = None
    if row.get("peer_asserted") is not True or row.get("tls_verified") is not False:
        problems.append(f"{where}: must say peer_asserted true and tls_verified false")
    host = row.get("host")
    if not isinstance(host, str) or (host == "" and status != "skipped"):
        problems.append(f"{where}: host is not a string (empty only on a skipped row)")
    port = row.get("port")
    if not _is_int(port) or not 1 <= int(port) <= 65535:
        problems.append(f"{where}: port {port!r} is not an integer 1-65535")
    for name in ("path_id", "vantage"):
        if not _is_text(row.get(name)):
            problems.append(f"{where}: receipt field {name} is missing or empty")
    started = row.get("started_utc")
    if not isinstance(started, str) or not _STAMP.fullmatch(started):
        problems.append(f"{where}: started_utc {started!r} is not YYYY-MM-DDTHH:MM:SSZ")
    duration = row.get("duration_ms")
    if not _is_int(duration) or int(duration) < 0:
        problems.append(f"{where}: duration_ms {duration!r} is not a non-negative integer")
    for name in ("detail", "peer_address", "tls_version"):
        if name in row and not _is_text(row[name]):
            problems.append(f"{where}: {name} is present but not a non-empty string")
    length = row.get("chain_length")
    if "chain_length" in row and (not _is_int(length) or int(length) < 1):
        problems.append(f"{where}: chain_length {length!r} is not a positive integer")
    if status is None:
        return problems
    if status != "captured":
        for name in ("certificates", "embedded_sct_log_ids"):
            if name in row:
                problems.append(f"{where}: carries {name} but is not captured")
        if not _is_text(row.get("detail")):
            problems.append(f"{where}: a {status} row must say why in detail")
        if (status == "limit") != ("chain_length" in row):
            problems.append(f"{where}: chain_length belongs on a limit row and only there")
        if status == "skipped" and "peer_address" in row:
            problems.append(f"{where}: a skipped row has no peer_address")
        return problems
    certificates = row.get("certificates")
    if not certificates or not isinstance(certificates, list):
        return [*problems, f"{where}: captured without retained certificates"]
    if len(certificates) > MAX_CERTIFICATES:
        # Not one certificate is looked at: a row past the cap is not a contract row, and 200 base64
        # decodes of hostile input are work this refusal does not need.
        return [
            *problems,
            f"{where}: {len(certificates)} certificates retained; at most {MAX_CERTIFICATES}",
        ]
    if row.get("chain_length") != len(certificates):
        problems.append(f"{where}: chain_length is not the {len(certificates)} retained")
    for name in ("peer_address", "tls_version"):
        if name not in row:
            problems.append(f"{where}: a captured row must carry {name}")
    scts = row.get("embedded_sct_log_ids")
    if scts is not None and (
        not isinstance(scts, list)
        or not all(isinstance(s, str) and _HEX64.fullmatch(s) for s in scts)
    ):
        problems.append(f"{where}: embedded_sct_log_ids is not a list of 64-digit lowercase hex")
    for expected, item in enumerate(certificates):
        problems.extend(_check_certificate(f"{where}: certificate {expected}", expected, item))
    return problems


def _check_certificate(where: str, expected: int, item: object) -> list[str]:
    if (
        not isinstance(item, dict)
        or item.get("position") != expected
        or not _is_int(item.get("position"))
    ):
        return [f"{where} is out of order or malformed"]
    problems = [
        f"{where} has unknown key {key!r}"
        for key in sorted(map(str, item))
        if key not in _CERTIFICATE_KEYS
    ]
    spki = item.get("spki_sha256")
    if spki is not None and not (isinstance(spki, str) and _HEX64.fullmatch(spki)):
        problems.append(f"{where}: spki_sha256 is neither 64 lowercase hex nor null")
    raw = decode_der(item)
    if isinstance(raw, str):
        return [*problems, f"{where}: {raw}"]
    if hashlib.sha256(raw).hexdigest() != item.get("sha256"):
        problems.append(f"{where}: sha256 does not match its retained bytes")
    return problems


def decode_der(item: Mapping[str, Any]) -> bytes | str:
    """The retained raw bytes, or the reason there are none. The length is checked before decoding."""
    encoded = item.get("der_b64")
    if not isinstance(encoded, str):
        return "no retained raw bytes (der_b64 missing)"
    if len(encoded) > MAX_B64:
        return f"der_b64 is {len(encoded)} characters; past the {MAX_CERTIFICATE_BYTES}-octet cap"
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return "der_b64 is not base64 (PEM armour or text is not retained raw DER)"
    if not raw:
        return "der_b64 decodes to no bytes"
    return raw


# ---------------------------------------------------------------------------------------------- asn1core


def find_asn1core(explicit: str | None) -> Path | None:
    """`asn1core/tools/collect_anchors.py` by path: `--asn1core`, then `$ASN1CORE_ROOT`, then a sibling."""
    candidates: list[Path] = []
    for root in (explicit, os.environ.get("ASN1CORE_ROOT")):
        if root:
            candidates += [Path(root) / "tools" / "collect_anchors.py", Path(root)]
    here = Path(__file__).resolve().parent
    for _ in range(4):
        candidates.append(here.parent / "asn1core" / "tools" / "collect_anchors.py")
        here = here.parent
    return next((c for c in candidates if c.is_file() and c.name == "collect_anchors.py"), None)


def armour(der: bytes) -> bytes:
    """One CERTIFICATE block around `der`, base64 in 64-character lines."""
    text = base64.b64encode(der)
    lines = [text[i : i + 64] for i in range(0, len(text), 64)]
    body = b"\n".join(lines)
    return b"-----BEGIN CERTIFICATE-----\n" + body + b"\n-----END CERTIFICATE-----\n"


def read_spki(script: Path, ders: Mapping[str, bytes]) -> dict[str, str]:
    """Certificate SHA-256 to SPKI SHA-256, as asn1core's reader states it. A certificate it refused is missing.

    The certificates are armoured into one PEM file in a temporary directory outside the repository and the
    data directory, and read with `--pem`. Armouring is base64 and two boundary lines, the inverse of the text
    handling `check_spki_artifact.extract_dir` does; nothing here looks inside the DER. `--der-dir` is not used
    because the reader hashes each input path with `read_bytes()`, which raises on a directory on Windows
    (measured 2026-11-14: `PermissionError` from `collect_anchors.py` line 297). argv is a list, never a shell.
    """
    if not ders:
        return {}
    with tempfile.TemporaryDirectory(prefix="host_reach_") as scratch:
        bundle = Path(scratch) / "presented.pem"
        bundle.write_bytes(b"".join(armour(der) for der in ders.values()))
        out = Path(scratch) / "identity.json"
        argv = [
            sys.executable,
            str(script),
            "--program",
            "host-reach",
            "--pem",
            str(bundle),
            "--out",
            str(out),
        ]
        try:
            done = subprocess.run(  # noqa: S603 - argv is a list, against a script resolved by path
                argv, capture_output=True, text=True, timeout=900
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RefusalError(f"asn1core's reader could not run: {type(exc).__name__}") from exc
        # Exit 1 with an artifact written is the reader saying it framed none of them, which is an answer
        # (every position unread); any other failure, or no artifact, means it did not answer at all.
        if done.returncode not in (0, 1) or not out.is_file():
            detail = ((done.stdout or "") + (done.stderr or "")).strip()[:300]
            raise RefusalError(f"asn1core's reader exited {done.returncode}: {detail}")
        try:
            identity = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RefusalError(f"asn1core's reader wrote no JSON: {type(exc).__name__}") from exc
    found: dict[str, str] = {}
    for row in identity.get("certificates") or []:
        if (
            isinstance(row, dict)
            and isinstance(row.get("sha256"), str)
            and isinstance(row.get("spki_sha256"), str)
        ):
            found[row["sha256"]] = row["spki_sha256"]
    return found


# ------------------------------------------------------------------------------------------- programs


def load_programs(
    data: Path, wanted: tuple[str, ...]
) -> tuple[dict[str, Any], dict[str, dict[str, list[str]]]]:
    """Each program's state, and for every program read, SPKI digest to the certificate digests listing it.

    Only `<program>.spki.json` directly in the data directory is read, where `check_spki_artifact.py` writes
    it; its scratch copies under `tmp/` are a reader's intermediate output, not an artifact.
    """
    found = {
        p.name.removesuffix(SPKI_SUFFIX): p
        for p in sorted(data.glob(f"*{SPKI_SUFFIX}"))
        if p.is_file()
    }
    states: dict[str, Any] = {}
    keys: dict[str, dict[str, list[str]]] = {}
    for program in sorted(set(wanted) | set(found)):
        path = found.get(program)
        if path is None:
            states[program] = {
                "state": UNREAD,
                "artifact": None,
                "why": "no key artifact in the data directory",
            }
            continue
        try:
            raw = path.read_bytes()
            doc = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            states[program] = {
                "state": UNREAD,
                "artifact": path.name,
                "why": f"not JSON ({type(exc).__name__})",
            }
            continue
        index: dict[str, list[str]] = {}
        rows = doc.get("certificates") if isinstance(doc, dict) else None
        shape_ok = (
            isinstance(doc, dict)
            and (doc.get("artifact"), doc.get("version")) == SPKI_ARTIFACT
            and isinstance(rows, list)
        )
        if shape_ok and isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                spki, cert = row.get("spki_sha256"), row.get("sha256")
                if (
                    isinstance(spki, str)
                    and _HEX64.fullmatch(spki)
                    and isinstance(cert, str)
                    and _HEX64.fullmatch(cert)
                ):
                    index.setdefault(spki, []).append(cert)
        if not shape_ok:
            states[program] = {
                "state": UNREAD,
                "artifact": path.name,
                "why": "not a version 1 key identity artifact with a certificates list",
            }
            continue
        keys[program] = {k: sorted(set(v)) for k, v in index.items()}
        states[program] = {
            "state": "read",
            "artifact": path.name,
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "keys": len(index),
        }
    return states, keys


# ------------------------------------------------------------------------------------------------ join


def join(
    doc: Mapping[str, Any],
    script: Path,
    states: Mapping[str, Any],
    keys: Mapping[str, Mapping[str, list[str]]],
) -> list[dict[str, Any]]:
    """One output row per input row, in input order. Raises `RefusalError` when a digest contradicts asn1core."""
    rows: list[dict[str, Any]] = doc["rows"]
    ders: dict[str, bytes] = {}
    for row in rows:
        for item in row.get("certificates") or []:
            raw = decode_der(item)
            if isinstance(raw, bytes):
                ders[item["sha256"]] = raw
    derived = read_spki(script, ders)

    out: list[dict[str, Any]] = []
    for row in rows:
        host = row["host"]
        entry: dict[str, Any] = {
            "host": host,
            "port": row["port"],
            "status": row["status"],
            "peer_asserted": row["peer_asserted"],
            "tls_verified": row["tls_verified"],
            "positions": [],
            "limits": [],
        }
        if not is_dns_name(host):
            entry["limits"].append(
                "host is not a DNS name; carried verbatim as a label and joined on nothing else"
            )
        if row["status"] == "limit":
            entry["chain_length"] = row["chain_length"]
            entry["limits"].append(
                "the capture kept no certificates past its cap, so no position was joined"
            )
        elif row["status"] != "captured":
            entry["limits"].append(
                f"no chain was captured ({row['status']}), so no position was joined"
            )
        for item in row.get("certificates") or []:
            entry["positions"].append(
                _position(host, item, derived.get(item["sha256"]), states, keys, entry["limits"])
            )
        out.append(entry)
    return out


def _position(
    host: str,
    item: Mapping[str, Any],
    derived: str | None,
    states: Mapping[str, Any],
    keys: Mapping[str, Mapping[str, list[str]]],
    limits: list[str],
) -> dict[str, Any]:
    stated, position = item.get("spki_sha256"), item["position"]
    if stated is not None and derived is not None and stated != derived:
        raise RefusalError(
            f"{host!r} position {position}: certledger recorded spki_sha256 {stated}, asn1core reads {derived}"
        )
    key = stated if stated is not None and derived is not None else None
    if key is None:
        side = (
            "certledger recorded none"
            if stated is None
            else "asn1core's reader refused the certificate"
        )
        limits.append(
            f"position {position}: no SPKI digest ({side}); every program is unread for it"
        )
    programs: dict[str, str] = {}
    listed: dict[str, list[str]] = {}
    for program, state in states.items():
        if key is None or state["state"] != "read":
            programs[program] = UNREAD
        elif key in keys[program]:
            programs[program] = PRESENT
            listed[program] = list(keys[program][key])
        else:
            programs[program] = ABSENT
    return {
        "position": position,
        "sha256": item["sha256"],
        "spki_sha256": key,
        "programs": programs,
        "listed_certificates": listed,
    }


def build(input_path: Path, data: Path, script: Path, wanted: tuple[str, ...]) -> dict[str, Any]:
    """The whole `host-reach/1` document, or `RefusalError`. Nothing is written here."""
    doc = read_input(input_path)
    problems = check_document(doc)
    if problems:
        shown = "; ".join(problems[:5]) + (
            f"; and {len(problems) - 5} more" if len(problems) > 5 else ""
        )
        raise RefusalError(f"{len(problems)} contract problem(s): {shown}")
    states, keys = load_programs(data, wanted)
    hosts = join(doc, script, states, keys)
    return {
        "schema": OUTPUT_SCHEMA,
        "input": {
            "schema": INPUT_SCHEMA,
            "sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "rows": len(hosts),
        },
        "reader": READER,
        "limits": list(LIMITS),
        "programs": states,
        "hosts": hosts,
    }


def render(doc: Mapping[str, Any]) -> bytes:
    """Byte-stable: sorted keys, ASCII-escaped, so a hostile host name cannot change the file's encoding."""
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--input", required=True, metavar="PATH", help="a certledger.host-chain/1 document"
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument(
        "--out", default=None, metavar="PATH", help="defaults to <data>/host/host-reach.json"
    )
    parser.add_argument(
        "--asn1core",
        default=None,
        metavar="PATH",
        help="asn1core checkout or its collect_anchors.py",
    )
    parser.add_argument(
        "--program",
        action="append",
        default=None,
        metavar="NAME",
        help="a program to report (repeatable); defaults to the stores check_spki_artifact.py names",
    )
    args = parser.parse_args(argv)

    data = Path(args.data)
    out = Path(args.out) if args.out else data / "host" / "host-reach.json"
    script = find_asn1core(args.asn1core)
    if script is None:
        print(
            "cannot find asn1core/tools/collect_anchors.py; pass --asn1core or set ASN1CORE_ROOT. Nothing written.",
            file=sys.stderr,
        )
        return 3
    try:
        doc = build(Path(args.input), data, script, tuple(args.program or DEFAULT_PROGRAMS))
    except RefusalError as exc:
        print(f"REFUSED: {exc}. Nothing written.", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_name(out.name + ".partial")
    partial.write_bytes(render(doc))
    partial.replace(out)
    positions = sum(len(h["positions"]) for h in doc["hosts"])
    print(f"{len(doc['hosts'])} host row(s), {positions} position(s) joined -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
