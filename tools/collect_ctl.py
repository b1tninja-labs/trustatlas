"""Pin Microsoft's published root-program and blocklist CTLs as bytes, and decode nothing.

The other collectors here read formats that are already text or PEM: `certdata.txt`,
`-----BEGIN CERTIFICATE-----` blocks. Microsoft's program is published differently — a CAB
(`application/vnd.ms-cab-compressed`) wrapping one member, `authroot.stl`, whose entries are signed
trust blobs in a Microsoft binary format. Unpacking a CAB and walking CTL records to produce "which
roots does the Windows program trust" is protocol logic, and `AGENTS.md` is unambiguous about where
that belongs: not here. A second, laxer parser of a trust structure is the one thing a trust map
cannot survive.

So this does the part that is honest from a Linux container: fetch, record the exact bytes' SHA-256
with a timestamp, and refuse to report a membership count it cannot derive. The pinned hash is not a
consolation prize — it is the only integrity anchor available, because **both URLs are plain HTTP**
and nothing in transit protects them except the signature inside the CTL, which is exactly the check
`pkix` would perform and which does not exist yet. Until then the artifact means what it says: bytes
as delivered over HTTP on this date. A future decoder can confirm it was fed these same bytes.

Usage:
    python tools/collect_ctl.py --data /data
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCES: dict[str, list[str]] = {
    "windows.authroot_ctl": [
        "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab",
    ],
    "windows.disallowed_ctl": [
        "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab",
    ],
}
UA = "trustatlas-collect-ctl/0 (research; read-only; see repository README)"
MAX_BYTES = 32 * 1024 * 1024


def fetch(candidates: list[str]) -> tuple[bytes, str, list[str], str | None]:
    """First candidate that serves a CAB. Attempts are kept, because a dead URL is a fact.

    No TLS context is passed on purpose: these are `http` URLs, and silently upgrading or failing
    would hide the thing worth recording. The transport is written into the artifact instead.
    """
    attempts: list[str] = []
    for url in candidates:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": UA})  # noqa: S310
            with urllib.request.urlopen(request, timeout=90.0) as response:  # noqa: S310
                ctype = str(response.headers.get("Content-Type") or "")
                body = response.read(MAX_BYTES + 1)
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            attempts.append(f"{type(exc).__name__}: {str(exc)[:70]} - {url}")
            continue
        if not body.startswith(b"MSCF"):
            attempts.append(
                f"Content-Type {ctype!r}, body is not a CAB ({len(body)} octets) - {url}"
            )
            continue
        return body, url, attempts, ctype
    return b"", "", attempts, None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()

    raw_dir = Path(args.data) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for name, candidates in SOURCES.items():
        cached = raw_dir / f"{name}.cab"
        if cached.is_file() and not args.refresh:
            payload = cached.read_bytes()
            source = str(cached) + " (cache)"
            ctype, attempts = "application/vnd.ms-cab-compressed", []
        else:
            payload, source, attempts, ctype = fetch(candidates)
            if not payload:
                for attempt in attempts:
                    print(f"  ruled out: {attempt}", file=sys.stderr)
                records.append(
                    {"source_id": name, "error": "unavailable", "attempts": attempts}
                )
                continue
            cached.write_bytes(payload)
        records.append(
            {
                "source_id": name,
                "url": source,
                "media_type": ctype,
                "octets": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "transport": "http"
                if source.startswith("http://")
                else "https-or-cache",
                "ruled_out": attempts,
                "decoded": False,
            }
        )

    doc = {
        "artifact": "trustatlas.ctl.collect",
        "version": 1,
        "program": "Microsoft/Windows program, as published CTLs",
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(
            timespec="seconds"
        ),
        "provenance": {
            "method": "GET, check the CAB magic, hash the bytes",
            "decode": (
                "not attempted. A CTL's entries are signed trust blobs in a Microsoft binary format;"
                " enumerating them is pkix's work, and the signature inside the CTL is the only"
                " integrity protection these plain-HTTP URLs have. A membership count produced here"
                " would be a guess with a JSON wrapper."
            ),
        },
        "sources": records,
        "counts": {
            "pinned": sum(1 for r in records if "sha256" in r),
            "unavailable": sum(1 for r in records if r.get("error")),
            "certificates_enumerated": 0,
        },
    }
    out = Path(args.data) / "store" / "microsoft.ctl.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))
    for record in records:
        if "sha256" in record:
            print(
                f"  {record['source_id']}: {record['octets']} octets over {record['transport']}, "
                f"sha256 {record['sha256'][:24]}... (entries not decoded)"
            )
        else:
            print(f"  {record['source_id']}: unavailable", file=sys.stderr)
    print(f"-> {out}")
    return 0 if doc["counts"]["pinned"] == len(SOURCES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
