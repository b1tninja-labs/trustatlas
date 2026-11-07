"""Collect Mozilla's NSS built-ins as an artifact: label, hash, and the trust bits NSS states.

The program that most other programs copy from, read at its source. `certdata.txt` is a text dump of
PKCS #11 objects, and everything this needs is text: `CKA_LABEL` names the certificate, `CKA_VALUE`
holds its DER as `\\ooo` octal escapes, and `CKA_TRUST_* CK_TRUST CKT_NSS_*` states what NSS is
configured to trust it for. Splitting objects, unescaping octal and hashing is reading a file
format; reading an ASN.1 certificate is not what happens here, and that keeps `AGENTS.md`'s rule
intact - naming a subject from DER would be `asn1core`'s, whereas the label is a string the file
already contains.

Why this collector and not just another bundle: it is the one side of the derivation graph with an
authoritative list. If every certifi certificate hashes into NSS's set, "certifi derives from NSS
built-ins" stops being a claim about documentation and becomes a hash check that runs. NSS ships
some objects certifi does not (email-only roots, for instance), so the expected result is a subset
with a countable remainder, and both numbers are the answer.

Usage:
    python tools/collect_certdata.py --data M:\\trustatlas --refresh
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

URLS = (
    "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt",
    "https://raw.githubusercontent.com/nss-dev/nss/MAIN/security/nss/lib/ckfw/builtins/certdata.txt",
    "https://raw.githubusercontent.com/nss-dev/nss/master/security/nss/lib/ckfw/builtins/certdata.txt",
)
UA = "trustatlas-collect-certdata/0 (research; read-only; see repository README)"
MAX_BYTES = 64 * 1024 * 1024
LABEL_RE = re.compile(r'^CKA_LABEL (?:UTF8|ASCII) "(.*)"')
TRUST_RE = re.compile(r"^CKA_TRUST_(\w+) CK_TRUST (CKT_NSS_\w+)")


def unescape_octal(block: list[str]) -> bytes:
    """`\\ooo` escapes, one byte per group of three digits, which is all `MULTILINE_OCTAL` contains."""
    out = bytearray()
    for line in block:
        i = 0
        while i < len(line):
            if line[i] == "\\":
                digits = line[i + 1 : i + 4]
                if len(digits) == 3 and all(c in "01234567" for c in digits):
                    out.append(int(digits, 8))
                    i += 4
                    continue
            i += 1
    return bytes(out)


def parse(text: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """One record per certificate, keyed by SHA-256 of DER, merged with trust-only objects by label."""
    notes: list[str] = []
    by_hash: dict[str, dict[str, Any]] = {}
    trust_by_label: dict[str, dict[str, str]] = {}
    # Objects are separated by "# Object" comment lines; some builds have no separator, so an
    # unbroken run of attributes is also treated as one object by keying on the label seen last.
    label: str | None = None
    value: bytes | None = None
    trust: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("CKA_LABEL "):
            match = LABEL_RE.match(line)
            if match:
                if value is not None and label is not None:
                    digest = hashlib.sha256(value).hexdigest()
                    record = by_hash.setdefault(
                        digest, {"sha256": digest, "labels": [], "trust": {}}
                    )
                    if label not in record["labels"]:
                        record["labels"].append(label)
                    record["trust"].update(trust)
                    trust = {}
                    value = None
                elif trust and label is not None:
                    # A trust object names a certificate by label and carries no CKA_VALUE. Flushing
                    # it here is what stops its bits being attributed to whichever certificate comes
                    # next, which is how a parser like this one silently mislabels a whole store.
                    trust_by_label.setdefault(label, {}).update(trust)
                    trust = {}
                label = match.group(1)
        elif line.startswith("CKA_VALUE MULTILINE_OCTAL"):
            block: list[str] = []
            i += 1
            while i < len(lines) and lines[i] != "END":
                block.append(lines[i])
                i += 1
            value = unescape_octal(block)
            if not value:
                notes.append(
                    f"label {label!r}: CKA_VALUE decoded to zero bytes; skipped"
                )
                value = None
        elif (match := TRUST_RE.match(line)) and label is not None:
            trust[match.group(1)] = match.group(2).removeprefix("CKT_NSS_")
        i += 1
    if value is not None and label is not None:
        digest = hashlib.sha256(value).hexdigest()
        record = by_hash.setdefault(
            digest, {"sha256": digest, "labels": [], "trust": {}}
        )
        if label not in record["labels"]:
            record["labels"].append(label)
        record["trust"].update(trust)
    for label_name, bits in trust_by_label.items():
        match = next((r for r in by_hash.values() if label_name in r["labels"]), None)
        if match is None:
            notes.append(
                f"trust object labelled {label_name!r} matches no certificate; kept aside"
            )
            continue
        match["trust"].update(bits)
    return by_hash, notes


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument("--path", default=None, help="a certdata.txt already on disk")
    parser.add_argument(
        "--refresh", action="store_true", help="re-download even if cached"
    )
    args = parser.parse_args()

    raw_dir = Path(args.data) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    cached = raw_dir / "mozilla.nss.certdata.txt"
    if args.path:
        payload = Path(args.path).read_bytes()
        source = str(Path(args.path))
    elif cached.is_file() and not args.refresh:
        payload = cached.read_bytes()
        source = str(cached) + " (cache)"
    else:
        payload, source, attempts = b"", "", []
        for url in URLS:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": UA})  # noqa: S310
                with urllib.request.urlopen(  # noqa: S310
                    request, timeout=120.0, context=ssl.create_default_context()
                ) as response:
                    body = response.read(MAX_BYTES + 1)
            except (
                urllib.error.HTTPError,
                urllib.error.URLError,
                TimeoutError,
                OSError,
            ) as exc:
                attempts.append(f"{type(exc).__name__}: {str(exc)[:60]} - {url}")
                continue
            if not body.startswith(b"#"):
                attempts.append(f"body is not the PKCS #11 dump - {url}")
                continue
            payload, source = body, url
            break
        if not payload:
            for attempt in attempts:
                print(f"ruled out: {attempt}", file=sys.stderr)
            return 1
        if attempts:
            print(
                f"  {len(attempts)} candidate(s) ruled out before the one that served the dump"
            )
        cached.write_bytes(payload)
        (raw_dir / "mozilla.nss.certdata.attempts.json").write_bytes(
            (
                json.dumps({"won": source, "ruled_out": attempts}, indent=1) + "\n"
            ).encode("utf-8")
        )
    text = payload.decode("utf-8", errors="replace")

    by_hash, notes = parse(text)
    stated = sum(
        1
        for r in by_hash.values()
        if r["trust"].get("SERVER_AUTH") == "TRUSTED_DELEGATOR"
    )
    doc = {
        "artifact": "trustatlas.certdata.collect",
        "version": 1,
        "program": "Mozilla/NSS built-ins",
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(
            timespec="seconds"
        ),
        "provenance": {
            "source": source,
            "octets": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "method": "PKCS #11 object dump: CKA_LABEL, CKA_VALUE (MULTILINE_OCTAL), CKA_TRUST_*",
            "note": (
                "labels are strings the file carries; no certificate is decoded. Trust bits are "
                "recorded as the file states them: SERVER_AUTH=TRUSTED_DELEGATOR is what NSS is "
                "built with, not an evaluation of this build's policy."
            ),
        },
        "counts": {
            "certificates": len(by_hash),
            "stated_server_auth_trusted": stated,
            "unmatched_trust_objects": sum(
                1 for n in notes if "matches no certificate" in n
            ),
        },
        "anchors": sorted(
            (
                {
                    "sha256": digest,
                    "subject": record["labels"][0] if record["labels"] else None,
                    "labels": record["labels"],
                    "store": "nss",
                    "eku": [],
                    "eku_names": [],
                    "trust": record["trust"],
                }
                for digest, record in by_hash.items()
            ),
            key=lambda a: a["subject"] or "",
        ),
        "notes": notes,
    }
    out = Path(args.data) / "store" / "mozilla.nss.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(
        (json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    )
    print(
        f"NSS built-ins: {len(by_hash)} certificates, {stated} stated trusted for server "
        f"authentication ({len(payload)} octets, {len(notes)} notes) -> {out}"
    )
    for note in notes[:6]:
        print(f"  note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
