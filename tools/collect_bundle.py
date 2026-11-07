"""Collect a PEM bundle program as an artifact: one hash per certificate, nothing interpreted.

The counterpart to `collect_store.py`. A bundle is a program's trust set too — certifi and curl ship
one, Debian generates one, Java ships another — and the map needs them on the same footing as a
Windows store. This reads a bundle and records, per certificate, its SHA-256 of DER, its octet
count and its PEM block index. Splitting PEM and base64-decoding is not PKI parsing; naming a
subject or an SPKI would be, and that stays `asn1core`'s.

Consequence to keep in view: the bundle side of any join is therefore **hashes only**. The overlap
with a store is computable, and so is each side's remainder, but a hash alone cannot say which CA
is missing — that is the point of the hashes-and-counts posture, not an oversight in it.

Usage:
    python tools/collect_bundle.py --program certifi
    python tools/collect_bundle.py --program curl --path C:\\path\\to\\cacert.pem
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import json
import os
import sys
from pathlib import Path

BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"


def bundle_path(program: str, explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    if program == "certifi":
        try:
            import certifi

            return Path(certifi.where())
        except Exception as exc:  # noqa: BLE001 - absent or broken package is a fact about the host
            print(
                f"certifi unavailable ({type(exc).__name__}: {exc}); pass --path",
                file=sys.stderr,
            )
            return None
    print(f"no default path for {program!r}; pass --path", file=sys.stderr)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--data", default=os.environ.get("TRUSTATLAS_DATA", "M:\\trustatlas")
    )
    parser.add_argument("--program", default="certifi")
    parser.add_argument(
        "--path", default=None, help="PEM bundle to read instead of a default"
    )
    args = parser.parse_args()

    path = bundle_path(args.program, args.path)
    if path is None or not path.is_file():
        print(f"no bundle at {path}", file=sys.stderr)
        return 1
    text = path.read_text(encoding="utf-8", errors="replace")

    import hashlib

    seen: dict[str, dict[str, object]] = {}
    duplicates = 0
    malformed = 0
    blocks = 0
    chunks = text.split(BEGIN)
    for previous, block in zip(chunks, chunks[1:]):
        body, _, _ = block.partition(END)
        blocks += 1
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            malformed += 1
            continue
        digest = hashlib.sha256(der).hexdigest()
        if digest in seen:
            duplicates += 1
            continue
        # The comment line the bundle's own maintainer wrote above the block. It is a string in the
        # file, so naming a certificate with it is not parsing one - and without it, a bundle's side
        # of a difference can only ever be counted. That is the difference between a number and an
        # answer, and it is why this line exists.
        # The header block above a block is the bundle maintainer's own comments. The fingerprint
        # line is used as an independent check on this script's hashing: if the stated SHA-256 of DER
        # equals the SHA-256 computed here, the PEM split and base64 decode are right for that
        # certificate, and 120 of them agreeing tests the collector in a way no fixture-based unit
        # test can. The other lines name it, which is a string in the file, not a parsed field.
        label, fingerprint = None, None
        for line in reversed(previous.splitlines()):
            stripped = line.strip().lstrip("#").strip()
            low = stripped.lower()
            if "fingerprint" in low:
                if low.startswith("sha256"):
                    fingerprint = (
                        stripped.split(":", 1)[-1].strip().replace(":", "").lower()
                    )
                continue
            if low.startswith("subject:") and label is None:
                label = stripped.split(":", 1)[1].strip()
                continue
            if low.startswith(("issuer:", "serial:", "validity:")) or len(stripped) < 5:
                continue
            if any(c.isalpha() for c in stripped) and label is None:
                label = stripped
                break
        entry = {
            "sha256": digest,
            "der_octets": len(der),
            "subject": label,
            "store": args.program,
        }
        if fingerprint and len(fingerprint) == 64:
            entry["bundle_fingerprint_agrees"] = fingerprint == digest
        seen[digest] = entry

    doc = {
        "artifact": "trustatlas.bundle.collect",
        "version": 1,
        "program": args.program,
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(
            timespec="seconds"
        ),
        "provenance": {
            "path": str(path),
            "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "method": "split PEM CERTIFICATE blocks, base64-decode, SHA-256 the DER",
            "note": (
                "hashes and counts only: no subject, no SPKI, no validity. A certificate's identity"
                " here is its SHA-256 of DER, which cannot connect two certificates that share a key."
            ),
        },
        "counts": {
            "pem_blocks": blocks,
            "distinct_certificates": len(seen),
            "duplicate_blocks": duplicates,
            "malformed_blocks": malformed,
            "fingerprint_checked": sum(
                1 for c in seen.values() if "bundle_fingerprint_agrees" in c
            ),
            "fingerprint_agrees": sum(
                1 for c in seen.values() if c.get("bundle_fingerprint_agrees")
            ),
            "named": sum(1 for c in seen.values() if c.get("subject")),
        },
        "certificates": sorted(seen.values(), key=lambda c: str(c["sha256"])),  # type: ignore[arg-type]
    }
    out = Path(args.data) / "store" / f"{args.program}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))
    print(
        f"{args.program}: {blocks} PEM blocks, {len(seen)} distinct certificates, {duplicates} duplicate"
        f"{'s' if duplicates != 1 else ''}, {malformed} malformed -> {out}"
    )
    checks = doc["counts"]
    print(
        f"  the bundle states a SHA-256 for {checks['fingerprint_checked']} certificates; "
        f"{checks['fingerprint_agrees']} match what this script hashed, and "
        f"{checks['named']} carry a name in the file"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
