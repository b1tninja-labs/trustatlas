"""Re-derive the key-level identity of a store from the raw bytes we retained, and write it beside the artifact.

Every collector here stops at certificate SHA-256: `collect_bundle.py` splits armour and hashes DER,
`collect_certdata.py` unescapes octal and hashes DER, `collect_store.py` records what Windows states. None of
them can name a subject or a key, because naming those means parsing a certificate and `AGENTS.md` says that is
`asn1core`'s job — growing a second, laxer PKI in the pipeline is the one thing a trust map cannot survive. So
this file parses nothing either. It **calls `asn1core/tools/collect_anchors.py` as a subprocess, by path**, over
the raw payload already sitting in the data directory, and writes what comes back to `<name>.spki.json`.

Why that artifact is worth having: the join key a map of cross-signs needs is SPKI SHA-256, because a root and
its cross-signed twin are two certificates holding one key. `join_programs.py` joins on certificate SHA-256, so
where a store carries both twins it counts them twice and reports less agreement than there is. Measured once by
hand against the Windows machine store — 68 distinct certificates, 67 distinct keys — and then thrown away,
because nothing wrote it down and the artifacts keep no DER. This tool turns that one-off measurement into a
rerunnable command whose output lives next to the store artifact it describes.

**Refusal is the point of the second half of this file.** A key-level claim derived from bytes that are no
longer on disk cannot be re-derived, so it is not evidence — and an artifact that quietly carries stale digests
from a previous run is worse than none, because the next reader has no way to tell. So when the raw payload is
absent this exits non-zero, writes nothing at all (not even a record of the refusal: see `--report`), and names
the path it looked for. The same holds for a store whose bytes were never retained in the first place — the
reader that printed them (`keytool`, `node`, an installed certifi) is gone with its output, and the Windows
provider answers only on its own machine.

Three states are kept apart rather than collapsed into a nonzero exit:

* **derivable** — raw is on disk; `asn1core` read it; `<name>.spki.json` was written.
* **refused** — the store artifact exists but its raw payload does not. Non-zero, nothing written.
* **absent** — no such store artifact in this data directory. Skipped, reported, and only fatal under
  `--require`, because asking for a store nobody collected is a typo and not a finding.

Usage:
    python tools/check_spki_artifact.py --list --data M:\\trustatlas
    python tools/check_spki_artifact.py --all --data M:\\trustatlas
    python tools/check_spki_artifact.py curl --data M:\\trustatlas
    python tools/check_spki_artifact.py --report --data M:\\trustatlas
"""

from __future__ import annotations

import argparse
import binascii
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

DERIVABLE, REFUSED, ABSENT = "derivable", "refused", "absent"

# The stores whose bytes are retained in `raw/`, and the shape `asn1core`'s reader expects. This is a list of
# *retained payloads*, not of trust stores: certifi, java, node, python.schannel and windows arrive through a
# reader or an OS provider that holds no copy afterwards, so they have nothing to re-derive from and are said
# so below rather than left out of the table.
SOURCES: dict[str, dict[str, Any]] = {
    "curl": {
        "raw": "raw/curl.pem",
        "kind": "pem",
        "artifact": "store/curl.json",
        "spki": "curl.spki.json",
        "retained_by": "collect_bundle.py --url writes what it fetched before indexing it",
    },
    "android.aosp": {
        "raw": "raw/android.aosp.tar.gz",
        "kind": "tar-pem",
        "artifact": "store/android.aosp.json",
        "spki": "android.aosp.spki.json",
        "retained_by": "collect_bundle.py --url --tar keeps the gitiles archive",
    },
    "mozilla.nss": {
        "raw": "raw/mozilla.nss.certdata.txt",
        "kind": "certdata",
        "artifact": "store/mozilla.nss.json",
        "spki": "mozilla.nss.spki.json",
        "retained_by": "collect_certdata.py caches the dump it fetches",
    },
    # Added 2026-11-15, when the readers below started keeping what they read (`raw/<program>.pem` for bundles
    # and readers, `raw/<artifact stem>/` of hash-named DER for the Windows provider with `--with-der`).
    "certifi": {
        "raw": "raw/certifi.pem",
        "kind": "pem",
        "artifact": "store/certifi.json",
        "spki": "certifi.spki.json",
        "retained_by": "collect_bundle.py --program certifi copies the installed file into raw/",
    },
    "node.bundled": {
        "raw": "raw/node.bundled.pem",
        "kind": "pem",
        "artifact": "store/node.bundled.json",
        "spki": "node.bundled.spki.json",
        "retained_by": "collect_bundle.py --reader node keeps the reader's stdout",
    },
    "python.schannel": {
        "raw": "raw/python.schannel.pem",
        "kind": "pem",
        "artifact": "store/python.schannel.json",
        "spki": "python.schannel.spki.json",
        "retained_by": "collect_bundle.py --reader py keeps the reader's stdout",
    },
    "java.cacerts": {
        "raw": "raw/java.cacerts.pem",
        "kind": "pem",
        "artifact": "store/java.cacerts.json",
        "spki": "java.cacerts.spki.json",
        "retained_by": "collect_java.py keeps keytool -list -rfc's output byte for byte",
    },
    "windows.machine": {
        "raw": "raw/windows.machine",
        "kind": "der-dir",
        "artifact": "store/windows.machine.json",
        "spki": "windows.machine.spki.json",
        "retained_by": "collect_store.py --with-der writes one verified DER file per certificate",
    },
    "windows.user": {
        "raw": "raw/windows.user",
        "kind": "der-dir",
        "artifact": "store/windows.user.json",
        "spki": "windows.user.spki.json",
        "retained_by": "collect_store.py --location CurrentUser --with-der",
    },
    "windows.user-ca": {
        "raw": "raw/windows.user-ca",
        "kind": "der-dir",
        "artifact": "store/windows.user-ca.json",
        "spki": "windows.user-ca.spki.json",
        "retained_by": "collect_store.py --location CurrentUser --store CA --with-der",
    },
}

# Why a store cannot be re-derived here, stated instead of omitted. An empty row in a table reads as an
# oversight; a reason reads as a measurement.
NOT_RETAINED: dict[str, str] = {
    # Every store in the table above can now keep its bytes; this stays for one that cannot, so its reason is
    # stated rather than omitted.
}

# The fields of an identity row that carry the *same* claim as the store artifact's own, and so are compared
# when it is re-derived. A digest is the join key; a serial is a number read out of the DER either way.
#
# `subject` and `label` are deliberately not here. What a store artifact carries under `subject` is a string its
# container printed — curl's `# Subject:` comment, an NSS `CKA_LABEL`, a keytool alias — while asn1core's
# `subject` is a distinguished name decoded from the bytes. Measured on curl: all 118 differ, every one because
# the comment omits the organisation and country instead of spelling them out. Comparing them would report 118
# differences on a bundle that agrees perfectly, and a check that cries on correct data gets ignored, which is
# the failure mode `ta.provenance_gate` warns about. Expiry is absent for a different reason: `expired` is
# measured against the clock, so it moves between two runs over identical bytes.
CLAIM_FIELDS = ("spki_sha256", "serial")


def now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def find_asn1core(explicit: str | None) -> tuple[Path | None, list[str]]:
    """`asn1core/tools/collect_anchors.py`, by path, plus every place looked.

    Resolved rather than imported on purpose: an import would put `asn1core` inside this process and make the
    pipeline depend on it at module load, while `pyproject.toml` declares no runtime dependency and the image
    installs nothing. A subprocess keeps the boundary where `AGENTS.md` drew it — this directory asks, that
    package parses — and the sibling checkout is found the same way `collect_java.py` finds a JDK: from an
    environment variable, then from the workspace layout, with the attempts kept as provenance.
    """
    looked: list[str] = []
    candidates: list[Path] = []
    if explicit:
        root = Path(explicit)
        # Either the package directory or the script itself may be handed over.
        candidates += [root / "tools" / "collect_anchors.py", root]
        looked.append(f"--asn1core {explicit}")
    env = os.environ.get("ASN1CORE_ROOT")
    if env:
        root = Path(env)
        candidates += [root / "tools" / "collect_anchors.py", root]
        looked.append(f"{root} (ASN1CORE_ROOT)")
    here = Path(__file__).resolve().parent
    for _ in range(4):
        candidates.append(here.parent / "asn1core" / "tools" / "collect_anchors.py")
        here = here.parent
    looked.append(
        "asn1core/tools/collect_anchors.py beside this repository, walking up four levels"
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate, looked
    return None, looked


def read_artifact(path: Path) -> dict[str, Any] | None:
    """The store artifact, or None. Absence is a state here and not an exception."""
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None
    return doc if isinstance(doc, dict) else None


def claimed_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The certificates a store artifact claims, keyed by nothing yet — read back, not remembered."""
    rows = doc.get("certificates") or doc.get("anchors") or []
    return [r for r in rows if isinstance(r, dict) and r.get("sha256")]


def run_reader(script: Path, kind: str, raw: Path, program: str, out: Path) -> tuple[int, str]:
    """Ask asn1core's reader for the identity of one retained payload.

    `--out` is a scratch path under the artifact's own name: the reader writes a document whose provenance
    block describes *its* command line, and this file restates what it found rather than passing that through
    as if this tool had run it. argv is a list, never a shell.
    """
    flag = {
        "pem": "--pem",
        "certdata": "--certdata",
        "tar-pem": "--der-dir",
        "der-dir": "--der-dir",
    }[kind]
    target = str(raw) if kind != "tar-pem" else str(extract_dir(raw, out))
    argv = [sys.executable, str(script), "--program", program, flag, target, "--out", str(out)]
    try:
        done = subprocess.run(  # noqa: S603 - argv is a list, against a script we just resolved
            argv, capture_output=True, text=True, timeout=900
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"reader could not run: {type(exc).__name__}: {exc}"
    detail = ((done.stdout or "") + "\n" + (done.stderr or "")).strip()[:400]
    return done.returncode, detail


def extract_dir(raw: Path, near: Path) -> Path:
    """Unpack a one-anchor-per-file archive into hash-named DER files for `--der-dir`.

    Android's AOSP store arrives as a gzipped tar of `<subject hash>.0` files, which is neither armour nor a
    PKCS #11 dump, so the reader's three input shapes do not name it. Splitting PEM and base64-decoding it is
    the same text handling `collect_bundle.index_pem` already does — nothing decodes a certificate here — and
    what leaves this function is DER octets on disk for `asn1core` to parse. Files are named by their own
    SHA-256, so two anchors cannot overwrite each other and the directory's names are themselves digests of
    what they hold.
    """
    import base64
    import io
    import tarfile

    # Not `.der`: collect_anchors hashes each input path with read_bytes(), which raises PermissionError on a
    # directory. The suffix stays on the files inside; the directory must not look like one of its inputs.
    dest = near.with_name(f"{near.stem}_der")
    if dest.is_dir():
        # Written by a previous run of this same command into the scratch area; rebuilt rather than trusted,
        # because the archive on disk is the fact and a stale directory would silently be read as current.
        for stale in dest.glob("*.der"):
            stale.unlink()
    else:
        dest.mkdir(parents=True, exist_ok=True)
    begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    written = 0
    with tarfile.open(fileobj=io.BytesIO(raw.read_bytes()), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            chunk = handle.read()
            while begin in chunk:
                start = chunk.index(begin) + len(begin)
                stop = chunk.find(end, start)
                if stop < 0:
                    break
                try:
                    der = base64.b64decode(b"".join(chunk[start:stop].split()), validate=True)
                except (ValueError, binascii.Error):
                    chunk = chunk[stop + len(end) :]
                    continue
                if der:
                    (dest / f"{hashlib.sha256(der).hexdigest()}.der").write_bytes(der)
                    written += 1
                chunk = chunk[stop + len(end) :]
    if not written:
        raise ValueError(f"{raw} held no decodable CERTIFICATE blocks")
    return dest


def claims(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Identity rows keyed by certificate digest, for comparison against what an artifact claims."""
    return {str(r.get("sha256", "")).lower(): r for r in rows if r.get("sha256")}


def compare(claimed: list[dict[str, Any]], derived: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Does the certificate set an artifact states match the one asn1core read from the raw bytes?

    This is `verify_provenance.py`'s internal-rederive check carried up to the key level: a difference means
    either the extractor moved under the artifact or the raw payload is not what was collected. The counts are
    split by which kind of claim broke, because "the set moved" and "a number in a row we both carry moved" are
    different findings and neither may be reported as the other. Names are not compared at all — see
    `CLAIM_FIELDS`.
    """
    got = claims(claimed)
    missing = sorted(set(got) - set(derived))
    extra = sorted(set(derived) - set(got))
    field_diffs: list[dict[str, Any]] = []
    for digest in sorted(set(got) & set(derived)):
        for field in CLAIM_FIELDS:
            left, right = got[digest].get(field), derived[digest].get(field)
            if left and right and str(left) != str(right):
                field_diffs.append(
                    {"sha256": digest, "field": field, "artifact": left, "derived": right}
                )
    return {
        "artifact_certificates": len(got),
        "derived_certificates": len(derived),
        "in_artifact_only": missing,
        "in_derived_only": extra,
        "compared_fields": list(CLAIM_FIELDS),
        "field_differences": field_diffs[:20],
        "field_difference_count": len(field_diffs),
        "certificate_sets_agree": not missing and not extra,
        # The check passes only when the sets match AND nothing shared was renumbered. A matching set with a
        # differing serial means two different documents hashing alike, which no reader should have to notice
        # by scrolling a table.
        "agrees": not missing and not extra and not field_diffs,
    }


def raw_digest(raw: Path) -> dict[str, Any]:
    """The retained payload's digest for the identity artifact's provenance.

    A file is hashed as it is. A directory of hash-named DER (`collect_store.py --with-der`) is hashed as its
    manifest: one `<name> <sha256 of the bytes>` line per file, sorted, so the digest moves when any file is
    added, removed or altered, and not when the directory is merely copied elsewhere."""
    if raw.is_dir():
        files = sorted(p for p in raw.iterdir() if p.is_file())
        manifest = "".join(
            f"{p.name} {hashlib.sha256(p.read_bytes()).hexdigest()}\n" for p in files
        )
        return {
            "raw_sha256": hashlib.sha256(manifest.encode("ascii")).hexdigest(),
            "raw_octets": sum(p.stat().st_size for p in files),
            "raw_files": len(files),
            "raw_digest_of": "the sorted manifest of '<file name> <sha256>' lines",
        }
    return {
        "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "raw_octets": raw.stat().st_size,
    }


def write_spki_artifact(
    data: Path, name: str, source: dict[str, Any], identity: dict[str, Any], script: Path
) -> tuple[Path, dict[str, Any]]:
    """Fold asn1core's rows onto the store artifact's own fields and write `<name>.spki.json`."""
    doc = read_artifact(data / source["artifact"]) or {}
    stored = claims(claimed_rows(doc))
    rows: list[dict[str, Any]] = []
    for row in identity.get("certificates") or []:
        digest = str(row.get("sha256", "")).lower()
        named = stored.get(digest) or {}
        # The store artifact's name fields are strings the container carried — a keystore alias, an NSS label,
        # a bundle comment — and asn1core's `subject` is read out of the DER. Both are kept, under their own
        # names, because they are different claims and collapsing them is how an alias becomes a subject.
        entry: dict[str, Any] = {
            "sha256": digest,
            "spki_sha256": row.get("spki_sha256"),
            "subject": row.get("subject"),
            "serial": row.get("serial"),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "key_alg_oid": row.get("key_alg_oid"),
            "der_octets": row.get("der_octets"),
            "encoding": row.get("encoding"),
        }
        # basicConstraints, keyUsage and extendedKeyUsage exactly as asn1core decoded them (its `dk.anchors-usage`),
        # with presence, criticality and an undecodable or duplicated status kept, and any `defects` asn1core
        # recorded for a row it read leniently. Carried through unread: what they mean for a chain is `pkix`'s.
        for field in ("extensions", "defects"):
            if row.get(field) not in (None, [], {}):
                entry[field] = row[field]
        for field in ("alias", "labels", "store", "trust", "eku"):
            if named.get(field) not in (None, [], {}):
                entry[f"artifact_{field}"] = named[field]
        if named.get("subject") and named["subject"] != row.get("subject"):
            entry["artifact_subject"] = named["subject"]
        rows.append(entry)

    counts = identity.get("counts") or {}
    keys = {str(r.get("spki_sha256")) for r in rows if r.get("spki_sha256")}
    shared: dict[str, list[str]] = {}
    for row in rows:
        shared.setdefault(str(row.get("spki_sha256")), []).append(str(row.get("sha256")))
    collapsed = {k: v for k, v in shared.items() if len(v) > 1}

    out = data / source["spki"]
    payload = {
        "artifact": "trustatlas.spki_identity",
        "version": 1,
        "program": identity.get("program", name),
        "derived_at": now(),
        "provenance": {
            "raw": str(data / source["raw"]),
            **raw_digest(data / source["raw"]),
            "reader": str(script),
            "reader_version": _git_head(script.parent.parent),
            "store_artifact": source["artifact"],
            "method": (
                f"re-derived from the retained payload by {script.name} in asn1core, invoked as a subprocess; "
                "this repository parsed nothing. spki_sha256 is the key-level join key, sha256 the "
                "certificate-level one, both over stored bytes and never a re-encoding."
            ),
            "retained_by": source["retained_by"],
            "note": (
                "identity only: no signature is verified and no path is validated. Rows carry asn1core's "
                "fields; anything the store artifact itself claimed about the same digest is prefixed "
                "`artifact_`, so a container's alias is never mistaken for a distinguished name."
            ),
        },
        "counts": {
            "certificates": len(rows),
            "distinct_keys": len(keys),
            "collapsed_by_key": len(collapsed),
            "refused_decode": counts.get("refused_decode", 0),
            "non_canonical": counts.get("non_canonical", 0),
            "expired": counts.get("expired", 0),
        },
        "keys_sharing_certificates": collapsed,
        "agreement_with_store_artifact": compare(claimed_rows(doc), claims(rows)),
        "certificates": sorted(rows, key=lambda r: str(r["sha256"])),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(payload, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    return out, payload


def _git_head(repo: Path) -> str | None:
    """The commit the reader ran from, so an artifact names the parser that produced it. None off a checkout."""
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv against a directory we just resolved
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    head = (done.stdout or "").strip()
    return head[:12] if done.returncode == 0 and head else None


def check_one(
    data: Path, name: str, source: dict[str, Any], script: Path, scratch: Path
) -> tuple[int, dict[str, Any]]:
    """One store: refuse without raw, otherwise derive and write. Returns an exit code and a report row."""
    raw = data / source["raw"]
    row: dict[str, Any] = {
        "store": name,
        "raw": str(raw),
        "kind": source["kind"],
        "spki_artifact": source["spki"],
    }
    if not (raw.is_dir() if source["kind"] == "der-dir" else raw.is_file()):
        # Refused, and nothing written. Not a row in an artifact either — see `--report`: the record of a
        # refusal belongs on stdout, where it cannot be mistaken for last week's successful derivation.
        print(
            f"  REFUSED {name}: raw payload {raw} is absent.\n"
            f"          Key-level identity cannot be re-derived from bytes this repository does not hold; "
            f"{source['artifact']} would carry digests from some earlier run and say nothing about today. "
            f"Re-collect first ({source['retained_by']}).",
            file=sys.stderr,
        )
        row.update({"state": REFUSED, "why": "raw payload absent"})
        return 1, row

    out = scratch / source["spki"]
    try:
        code, detail = run_reader(script, source["kind"], raw, name, out)
    except ValueError as exc:
        print(f"  REFUSED {name}: {exc}", file=sys.stderr)
        row.update({"state": REFUSED, "why": str(exc)})
        return 1, row
    if code != 0 or not out.is_file():
        # A reader that refuses is a fact about the payload, not a reason to write a partial artifact.
        print(f"  REFUSED {name}: asn1core exited {code}: {detail[:240]}", file=sys.stderr)
        row.update({"state": REFUSED, "why": f"reader exit {code}", "output": detail[:240]})
        return 1, row

    try:
        identity = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"  REFUSED {name}: reader output unreadable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        row.update({"state": REFUSED, "why": "reader output was not JSON"})
        return 1, row

    dest, payload = write_spki_artifact(data, name, source, identity, script)
    counts = payload["counts"]
    agree = payload["agreement_with_store_artifact"]
    print(
        f"  {name}: {counts['certificates']} certificates, {counts['distinct_keys']} distinct keys "
        f"({counts['collapsed_by_key']} key(s) hold more than one certificate), "
        f"{counts['refused_decode']} refused on decode -> {dest}"
    )
    if agree["certificate_sets_agree"]:
        print(
            f"    agrees with {source['artifact']}: the same "
            f"{agree['artifact_certificates']} certificate digests, "
            f"{agree['field_difference_count']} field difference(s)"
        )
    else:
        print(
            f"    DISAGREES with {source['artifact']}: {len(agree['in_artifact_only'])} only in the artifact, "
            f"{len(agree['in_derived_only'])} only in the raw bytes. The extractor or the payload moved; "
            "the key-level artifact is written anyway and carries both numbers.",
            file=sys.stderr,
        )
    row.update(
        {
            "state": DERIVABLE,
            "certificates": counts["certificates"],
            "distinct_keys": counts["distinct_keys"],
            "collapsed_by_key": counts["collapsed_by_key"],
            "refused_decode": counts["refused_decode"],
            "sets_agree": agree["certificate_sets_agree"],
            "field_difference_count": agree["field_difference_count"],
            "raw_sha256": payload["provenance"]["raw_sha256"],
        }
    )
    return 0, row


def write_report(data: Path, rows: list[dict[str, Any]]) -> Path:
    """A roll-up of every attempt, including the refusals.

    Written only when asked for, because an artifact that carries both successes and stale refusals under one
    timestamp invites exactly the misreading this tool exists to prevent: `verify_provenance.py`'s rule that a
    skipped check must never report green, applied to a file instead of a line. The per-store `<name>.spki.json`
    artifacts are written only on success, so their existence is itself the claim.
    """
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row["state"])] = counts.get(str(row["state"]), 0) + 1
    doc = {
        "artifact": "trustatlas.spki_status",
        "version": 1,
        "checked_at": now(),
        "provenance": {
            "method": (
                "each retained raw payload in the data directory was handed to asn1core's own anchor reader as "
                "a subprocess and its identity written beside the store artifact; nothing here parsed a "
                "certificate"
            ),
            "note": (
                "A row reading refused means the raw bytes are gone and no key-level claim exists for that "
                "store today. A row reading absent means no store artifact was collected into this data "
                "directory. Neither is a green, and neither is silent."
            ),
        },
        "counts": counts,
        "stores": rows,
    }
    out = data / "store" / "spki.status.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument(
        "stores",
        nargs="*",
        metavar="STORE",
        help=f"which stores to re-derive; one of {', '.join(SOURCES)}",
    )
    parser.add_argument("--all", action="store_true", help="every store with a retained payload")
    parser.add_argument(
        "--list",
        action="store_true",
        help="print what can and cannot be re-derived here, without running anything",
    )
    parser.add_argument(
        "--asn1core",
        default=None,
        metavar="PATH",
        help="path to an asn1core checkout or to its tools/collect_anchors.py; "
        "defaults to $ASN1CORE_ROOT, then the sibling directory of this repository",
    )
    parser.add_argument(
        "--scratch",
        default=None,
        metavar="DIR",
        help="where the reader's intermediate artifact goes; defaults to <data>/tmp",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="also write store/spki.status.json, the roll-up that names the refusals",
    )
    parser.add_argument(
        "--require",
        action="store_true",
        help="treat a named store with no artifact as a failure instead of a skip",
    )
    args = parser.parse_args(argv)

    if args.list:
        print("re-derivable, because the payload is retained in raw/:")
        for name, source in SOURCES.items():
            print(f"  {name:<14} {source['raw']:<32} via {source['kind']}")
        print("\nnot re-derivable here, and why:")
        for name, reason in NOT_RETAINED.items():
            print(f"  {name:<18} {reason}")
        return 0

    wanted = list(args.stores) or (list(SOURCES) if args.all else [])
    if not wanted:
        print(
            f"no store named; pass one of {', '.join(SOURCES)}, or --all, or --list",
            file=sys.stderr,
        )
        return 2
    unknown = [w for w in wanted if w not in SOURCES]
    if unknown:
        print(
            f"not a store this tool can re-derive: {', '.join(unknown)}\n"
            f"known: {', '.join(SOURCES)}\n"
            f"declined by design: {', '.join(NOT_RETAINED)}",
            file=sys.stderr,
        )
        return 2

    data = Path(args.data)
    script, looked = find_asn1core(args.asn1core)
    if script is None:
        print("cannot find asn1core/tools/collect_anchors.py. Looked at:", file=sys.stderr)
        for entry in looked:
            print(f"  {entry}", file=sys.stderr)
        print(
            "Pass --asn1core PATH or set ASN1CORE_ROOT. Nothing was written: a key-level artifact "
            "this tool cannot produce is better left absent than guessed at.",
            file=sys.stderr,
        )
        return 3

    scratch = Path(args.scratch) if args.scratch else data / "tmp"
    try:
        scratch.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"cannot create scratch directory {scratch}: {exc}", file=sys.stderr)
        return 3

    rows: list[dict[str, Any]] = []
    failures = 0
    for name in wanted:
        source = SOURCES[name]
        if not (data / source["artifact"]).is_file():
            # A store nobody collected here is a different thing from one whose bytes went missing, and the
            # exit code keeps them apart: only --require makes the first a failure.
            why = f"{source['artifact']} is not in {data}"
            print(f"  SKIP {name}: {why}", file=sys.stderr)
            rows.append({"store": name, "state": ABSENT, "why": why})
            failures += 1 if args.require else 0
            continue
        code, row = check_one(data, name, source, script, scratch)
        rows.append(row)
        failures += 1 if code else 0

    derived = sum(1 for r in rows if r["state"] == DERIVABLE)
    refused = sum(1 for r in rows if r["state"] == REFUSED)
    skipped = sum(1 for r in rows if r["state"] == ABSENT)
    print(
        f"\n{len(rows)} store(s): {derived} written, {refused} refused, {skipped} absent"
        + ("; GATE FAILURES" if failures else "")
    )
    if args.report:
        print(f"-> {write_report(data, rows)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
