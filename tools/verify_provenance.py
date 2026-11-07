"""Validate how each trust store's bytes reached us, and re-derive what we claimed about them.

The map is only as good as the chain behind it, and that chain has three links anyone can break on their own:
a **fetcher** (where the bytes came from, over what transport), an **extractor** (how anchors were read out of
the container), and this file, the **validator**. It answers the questions a reader is entitled to ask without
trusting any of us: does the file upstream publishes match the digest upstream publishes; is the copy in a git
repository the same bytes as the copy we hashed; do the anchors compiled into a Node binary match the list
checked into Node's source; and does re-running the extractor over the raw payload we retained still produce
the certificate set the artifact claims?

That last check is not hypothetical. Android's AOSP files each carry an OpenSSL text dump after the PEM, and a
label walk reading backwards from a block picked up the previous certificate's `Subject:` line: 148 of 149
names were wrong while every digest stayed correct, because digests never look at the text. A cross-channel
check passes that silently. Only re-derivation from retained raw catches an extractor moving under an artifact,
and that is what `--check` exists to fail on.

Verdicts, in the order they matter:

* `agree` -- the two sides match, on a channel where they must.
* `differs` -- they do not. Sometimes correct and interesting (an installed certifi is not today's git head),
  so it fails the gate only where the comparison is marked `must`.
* `unverifiable` -- the channel does not exist, refused us, or no raw was retained. Reported as such rather
  than dropped: a validator that skips a check and exits 0 is worse than no validator.

Usage:
    python tools/verify_provenance.py --check --data M:\\trustatlas
    python tools/verify_provenance.py --list
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
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_bundle import index_pem, pem_from_tar  # noqa: E402 - same directory, one implementation

UA = "trustatlas-provenance/1.0"
MUST, INFO = "must", "informational"

# Each check names the artifact it vouches for, the two sides compared, and whether agreement is required or
# merely interesting. URLs were confirmed reachable on 2026-11-07; the ones that returned 404 are kept as
# unverifiable rows so the next person does not re-guess them.
CHECKS: tuple[dict[str, Any], ...] = (
    {
        "id": "curl.published_digest",
        "artifact": "curl.json",
        "side_a": "raw/curl.pem hashed here",
        "side_b": "https://curl.se/ca/cacert.pem.sha256 as published",
        "kind": "digest_sibling",
        "url": "https://curl.se/ca/cacert.pem.sha256",
        "expect": MUST,
        "note": "curl publishes the digest of the very file we fetch, so the transport is checkable without "
        "trusting TLS alone. The only store in the map whose upstream hands us an integrity value.",
    },
    {
        "id": "curl.internal_rederive",
        "artifact": "curl.json",
        "side_a": "raw/curl.pem re-extracted now",
        "side_b": "the committed curl.json certificate set",
        "kind": "internal_rederive",
        "raw": "raw/curl.pem",
        "extractor": "index_pem",
        "expect": MUST,
        "note": "Guards the extractor rather than the store: a difference means this repository's code moved "
        "under the artifact, which is how a name ends up attached to the wrong certificate.",
    },
    {
        "id": "android.internal_rederive",
        "artifact": "android.aosp.json",
        "side_a": "raw/android.aosp.tar.gz re-extracted now",
        "side_b": "the committed android.aosp.json certificate set",
        "kind": "internal_rederive",
        "raw": "raw/android.aosp.tar.gz",
        "extractor": "pem_from_tar",
        "expect": MUST,
        "note": "The check the Android mislabelling would have failed had it existed first: the archive is "
        "retained precisely so the extractor can be run again without going back to Google's server, so a "
        "difference here means this repository's code moved under an artifact that is still being cited.",
    },
    {
        "id": "certifi.git_channel",
        "artifact": "certifi.json",
        "side_a": "the bundle the installed certifi package hashed at collection time",
        "side_b": "https://raw.githubusercontent.com/certifi/python-certifi/master/certifi/cacert.pem",
        "kind": "byte_mirror",
        "url": "https://raw.githubusercontent.com/certifi/python-certifi/master/certifi/cacert.pem",
        "expect": INFO,
        "note": "certifi's bundle is checked into git and also shipped in the wheel. Differing digests are the "
        "normal case -- an installed package is a release, the git blob is head -- and the pair is what makes a "
        "supply-chain question answerable: which commit produced the file on this machine. PyPI additionally "
        "publishes a SHA-256 per distribution file at /pypi/certifi/json, so the wheel itself is checkable.",
    },
    {
        "id": "nss.git_mirror",
        "artifact": "mozilla.nss.json",
        "side_a": "raw/mozilla.nss.certdata.txt fetched from hg.mozilla.org",
        "side_b": "https://github.com/mozilla/gecko-dev/raw/master/security/nss/lib/ckfw/builtins/certdata.txt",
        "kind": "byte_mirror",
        "url": "https://github.com/mozilla/gecko-dev/raw/master/security/nss/lib/ckfw/builtins/certdata.txt",
        "raw": "raw/mozilla.nss.certdata.txt",
        "expect": INFO,
        "note": "The same file over two independent distributions, Mercurial and a git mirror. Agreement says "
        "the mirror is current; disagreement measures how far behind it is, which matters because the mirror "
        "is where commit history, and therefore who changed the list, is readable. The Mercurial JSON log "
        "endpoint served HTML and gitiles returned 401 for +log?format=JSON, so authorship is readable from "
        "the git mirror and not from the canonical server.",
    },
    {
        "id": "node.source_header",
        "artifact": "node.bundled.json",
        "side_a": "the anchors the node binary handed to tls.rootCertificates",
        "side_b": "PEM strings extracted from src/node_root_certs.h at Node's git head",
        "kind": "embedded_source",
        "url": "https://raw.githubusercontent.com/nodejs/node/main/src/node_root_certs.h",
        "expect": INFO,
        "note": "A compiled-in store has no file on disk to audit, so the source header is the auditable "
        "channel -- 193,073 bytes of C string literals, each anchor named in a comment above its block, which "
        "is also why a store read out of the running binary arrives unnamed. The binary here is v25.9.0 and "
        "the header is head, so a difference is expected; the point is that 145 anchors are recoverable from "
        "the source by anyone.",
    },
    {
        "id": "java.upstream_list",
        "artifact": "java.cacerts.json",
        "side_a": "the cacerts keystore this JDK ships",
        "side_b": "unverified: make/data/cacerts and src/java.base/share/lib/security/cacerts both 404",
        "kind": "unavailable",
        "expect": INFO,
        "note": "Recorded as a negative so the guess is not repeated: the keystore Oracle ships was not at "
        "either candidate path in the openjdk git mirror on 2026-11-07, so there is no second channel yet. "
        "The local keystore remains re-derivable by running keytool, which is what the artifact records.",
    },
    {
        "id": "windows.os_channel",
        "artifact": "windows.machine.json",
        "side_a": "what the OS certificate provider returned on this host",
        "side_b": "no upstream file: the list arrives through Windows Update, and authroot.stl needs the CTL "
        "decoder that lives in pkix",
        "kind": "unavailable",
        "expect": INFO,
        "note": "Validated by re-running the provider on the same machine, never by a URL. A host-resident "
        "probe has no second channel by construction, which is worth stating instead of hiding behind a green.",
    },
)


def now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def get(url: str, timeout: float = 120.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": UA})  # noqa: S310
    with urllib.request.urlopen(  # noqa: S310
        request, timeout=timeout, context=ssl.create_default_context()
    ) as response:
        return response.read(64 * 1024 * 1024)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact_rows(data: Path, name: str) -> list[dict[str, Any]] | None:
    path = data / "store" / name
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("certificates") or doc.get("anchors") or []


def artifact_set(data: Path, name: str) -> set[str] | None:
    """The certificate digests an artifact claims, read back rather than remembered."""
    rows = artifact_rows(data, name)
    if rows is None:
        return None
    return {str(r.get("sha256", "")).lower() for r in rows} - {""}


def pem_spans_from_c(text: str) -> str:
    """Recover PEM from C string literals, the shape Node's root header stores anchors in.

    The header is a run of quoted lines with escaped newlines, so the literals are joined and unescaped before
    `index_pem` sees them. No certificate is parsed; the only knowledge here is how a C file holds a text file.
    """
    joined = "".join(m.group(1) for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', text))
    return joined.replace("\\n", "\n").replace('\\"', '"')


def run_check(check: dict[str, Any], data: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": check["id"],
        "artifact": check["artifact"],
        "kind": check["kind"],
        "expect": check["expect"],
        "side_a": check["side_a"],
        "side_b": check["side_b"],
        "note": check["note"],
    }
    kind = check["kind"]

    if kind == "unavailable":
        return {
            **result,
            "verdict": "unverifiable",
            "detail": "no second channel exists for this store",
        }

    if kind == "internal_rederive":
        raw = data / check["raw"]
        claimed = artifact_set(data, check["artifact"])
        if claimed is None:
            return {
                **result,
                "verdict": "unverifiable",
                "detail": f"{check['artifact']} is absent",
            }
        if not raw.is_file():
            return {
                **result,
                "verdict": "unverifiable",
                "detail": f"{raw} was not retained",
            }
        if check["extractor"] == "pem_from_tar":
            text, _members, _dumped = pem_from_tar(raw.read_bytes())
        else:
            text = raw.read_text(encoding="utf-8", errors="replace")
        seen, counts = index_pem(text, program=check["artifact"])
        got = set(seen)
        return {
            **result,
            "verdict": "agree" if got == claimed else "differs",
            "detail": f"re-derived {len(got)} vs artifact {len(claimed)}; added {len(got - claimed)}, "
            f"dropped {len(claimed - got)}, {counts['malformed_blocks']} malformed",
            "distinct": len(got),
        }

    try:
        payload = get(check["url"])
    except Exception as exc:  # noqa: BLE001 - a channel that will not answer is the finding, not a crash
        return {
            **result,
            "verdict": "unverifiable",
            "detail": f"{type(exc).__name__}: {exc}"[:240],
        }

    result["fetched_octets"] = len(payload)

    if kind == "digest_sibling":
        raw = data / "raw" / "curl.pem"
        if not raw.is_file():
            return {
                **result,
                "verdict": "unverifiable",
                "detail": "raw/curl.pem was not retained",
            }
        published = payload.decode("ascii", errors="replace").split()
        want = (published[0] if published else "").lower()
        got = sha256(raw.read_bytes())
        return {
            **result,
            "verdict": "agree" if want and want == got else "differs",
            "detail": f"published {want[:16]}... vs computed {got[:16]}...",
            "published_digest": want,
            "computed_digest": got,
        }

    if kind == "byte_mirror":
        # Prefer the raw payload we retained over whatever the artifact remembers: the check is the bytes we
        # hashed against the bytes the second channel carries, and an artifact that stored no digest of its
        # own should not make material that is sitting on disk unverifiable.
        ours = ""
        raw = data / check["raw"] if check.get("raw") else None
        side_a_label = f"{check['artifact']} provenance"
        if raw is not None and raw.is_file():
            ours = sha256(raw.read_bytes())
            side_a_label = raw.name
        else:
            path = data / "store" / check["artifact"]
            if path.is_file():
                doc = json.loads(path.read_text(encoding="utf-8"))
                ours = str(
                    (doc.get("provenance") or {}).get("file_sha256") or ""
                ).lower()
        theirs = sha256(payload)
        if not ours:
            return {
                **result,
                "verdict": "unverifiable",
                "detail": f"no digest on either side; channel digest {theirs[:16]}... recorded",
                "channel_digest": theirs,
            }
        return {
            **result,
            "verdict": "agree" if ours == theirs else "differs",
            "detail": f"channel {theirs[:16]}... vs {side_a_label} {ours[:16]}...",
            "channel_digest": theirs,
            "side_a_digest": ours,
        }

    claimed = artifact_set(data, check["artifact"])
    if claimed is None:
        return {
            **result,
            "verdict": "unverifiable",
            "detail": f"{check['artifact']} is absent",
        }
    source_text = pem_spans_from_c(payload.decode("utf-8", errors="replace"))
    markers = source_text.count("-----BEGIN CERTIFICATE-----")
    seen, counts = index_pem(source_text, program="node-source")
    source = set(seen)
    accounted = len(source) + counts["duplicate_blocks"] + counts["malformed_blocks"]
    return {
        **result,
        "verdict": "agree" if source == claimed else "differs",
        "detail": f"source {len(source)} anchors recovered from {markers} PEM markers vs binary "
        f"{len(claimed)}; in-source-only {len(source - claimed)}, in-binary-only {len(claimed - source)}",
        "source_anchors": len(source),
        "source_pem_markers": markers,
        # A lossless extraction accounts for every BEGIN marker as a distinct digest, a duplicate of one, or a
        # malformed block. If markers and accounted differ, the number of anchors is a property of this file's
        # C-literal join and not of Node, so the check reports the gap instead of hiding a small count.
        "extraction_lossless": markers == accounted,
        "markers_unaccounted": markers - accounted,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument(
        "--check", action="store_true", help="run every check and write the artifact"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the checks without touching the network",
    )
    args = parser.parse_args()

    if args.list:
        for check in CHECKS:
            print(
                f"{check['id']:<28} {check['kind']:<19} {check['expect']:<16} {check['artifact']}"
            )
        return 0

    data = Path(args.data)
    results = [run_check(check, data) for check in CHECKS]
    for row in results:
        print(f"{row['id']:<28} {row['verdict']:<13} {row['detail']}")

    gate = [r for r in results if r["verdict"] == "differs" and r["expect"] == MUST]
    counts: dict[str, int] = {}
    for row in results:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print(
        f"\n{len(results)} checks: "
        + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        + (
            f"; GATE FAILURES: {', '.join(r['id'] for r in gate)}"
            if gate
            else "; no must-agree check failed"
        )
    )

    out = data / "store" / "provenance.status.json"
    doc = {
        "artifact": "trustatlas.provenance.status",
        "version": 1,
        "checked_at": now(),
        "provenance": {
            "method": "each check compares two independent descriptions of the same material: a published "
            "digest against one computed here, a git blob against the bytes held at collection time, a "
            "source header's PEM against a running binary's anchors, or the current extractor against a "
            "committed artifact over retained raw",
            "note": "A green line is not an endorsement of a store. Verdicts are about channels: agree means "
            "two routes carried the same material, differs means they did not (often correct, and the detail "
            "says which), unverifiable means there was nothing to compare. Only checks marked must gate the "
            "exit code, so an informational difference between a release and a git head does not turn red.",
            "checks": len(results),
        },
        "counts": counts,
        "gate_failures": [r["id"] for r in gate],
        "results": results,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))
    print(f"-> {out}")
    return 1 if gate else 0


if __name__ == "__main__":
    raise SystemExit(main())
