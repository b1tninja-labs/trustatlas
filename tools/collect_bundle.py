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
    python tools/collect_bundle.py --program python.x --reader py --reader-arg=-c --reader-arg=CODE

A reader's own flags travel as `--reader-arg=VALUE`, joined by `=`: written as two words, a value that
starts with `-` is taken by argparse for an option and refused.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import io
import itertools
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from collections.abc import Iterable
from pathlib import Path

BEGIN = "-----BEGIN CERTIFICATE-----"
UA = "trustatlas-collect-bundle/0 (research; read-only; see repository README)"
END = "-----END CERTIFICATE-----"
# What the text above a block may be called when it carries no `subject:`/`owner:`/`alias:` key.
NAME_KEYS = ("subject", "alias")
# Base64 characters (line breaks included) one block may hold before it is counted as malformed unread.
# 1 MiB of text is about 768 KiB of DER, far above any trust anchor a program ships; the cap exists so a
# hostile 10 MB block ends as a count rather than a digest of whatever it was.
MAX_BLOCK_CHARS = 1 << 20
# The historical labels RFC 7468 section 5.1 names: generators MUST NOT emit them, and parsers SHOULD NOT treat
# them as equivalent to "CERTIFICATE", with backwards compatibility (potentially with a warning) allowed as
# an exception. This file takes the strict side: such a block is counted and warned about, never hashed, so
# it cannot enter a join; the bundle itself is still read rather than refused.
LEGACY_BEGINS = ("-----BEGIN X509 CERTIFICATE-----", "-----BEGIN X.509 CERTIFICATE-----")


def bundle_path(program: str, explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    if program == "certifi":
        try:
            import certifi

            return Path(certifi.where())
        except Exception as exc:  # absent or broken package is a fact about the host
            print(
                f"certifi unavailable ({type(exc).__name__}: {exc}); pass --path",
                file=sys.stderr,
            )
            return None
    print(f"no default path for {program!r}; pass --path", file=sys.stderr)
    return None


def index_pem(
    text: str, *, program: str, name_key: str = "subject"
) -> tuple[dict[str, dict[str, object]], dict[str, int]]:
    """Split PEM CERTIFICATE blocks, base64-decode, SHA-256 the DER, and count what was seen.

    One implementation on purpose. `join_programs.py` compares SHA-256 of DER across programs, so two
    collectors that derive the digest slightly differently would report an overlap that is a property of
    the code rather than of the trust sets. Any new reader imports this rather than growing its own split.

    Every row carries both `subject` and `alias`, `None` when the file does not say. `subject` comes only
    from a `subject:` or `owner:` line, `alias` only from an `alias:`/`alias name:` line (which is how
    `pem_from_tar` records an archive member name). In `keytool -list -rfc` output the alias is a nickname
    the keystore chose and not a subject; recording it as one would be the exact overstatement this
    repository's honesty rule refuses. `name_key` ("subject" or "alias") only says what an *unkeyed* comment
    line above a block may be called, and that line is written to `name_key` alone, never to both.

    A header region holding an OpenSSL `Certificate:` text dump is discarded whole and counted in
    `header_dumps_discarded`; an unterminated block, an empty one, one over `MAX_BLOCK_CHARS` and one that is
    not base64 are counted in `malformed_blocks`. Nothing in the input ends in an exception.

    Returns the digest index and the counts; nothing here names a subject, an SPKI or a validity, because
    naming those is `asn1core`'s job and not this file's.
    """
    if name_key not in NAME_KEYS:
        raise ValueError(f"name_key must be one of {NAME_KEYS}, not {name_key!r}")
    seen: dict[str, dict[str, object]] = {}
    duplicates = 0
    malformed = 0
    blocks = 0
    dumps_discarded = 0
    # The boundaries are matched as exact, case-sensitive strings (RFC 7468 erratum 4508, verified: the
    # encapsulation boundaries are case-sensitive), so `-----begin certificate-----` is not a block here.
    chunks = text.split(BEGIN)
    for previous, block in itertools.pairwise(chunks):
        body, found_end, _ = block.partition(END)
        # Only the text after the previous block's END marker describes this one. Without that cut, a
        # bundle with no per-block comments -- node's compiled-in set -- labels every block after the
        # first with the trailing "-----END CERTIFICATE-----" line: measured 144 of 145 anchors
        # "named", each name a PEM delimiter.
        header = previous.rpartition(END)[2]
        blocks += 1
        # An unterminated block and an oversized one are counted refusals: the first is a truncated file,
        # the second is a hostile or corrupt one, and neither is allowed to become a digest or a crash.
        if not found_end or len(body) > MAX_BLOCK_CHARS:
            malformed += 1
            continue
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            malformed += 1
            continue
        if not der:
            malformed += 1
            continue
        digest = hashlib.sha256(der).hexdigest()
        if digest in seen:
            duplicates += 1
            continue
        # An OpenSSL `Certificate:` text dump in the header region describes some *other* certificate --
        # AOSP appends one below each PEM, so above the next block it is the previous anchor's -- and its
        # `Subject:` line would be read as this block's name. `pem_from_tar` drops such dumps, but callers
        # that bypass it (`collect_java.py`, `verify_provenance.py`, a reader) reach here directly, so the
        # whole region is discarded unread and counted rather than mined for a name.
        if any(line.strip().lstrip("#").strip() == "Certificate:" for line in header.splitlines()):
            dumps_discarded += 1
            header = ""
        # The header region above a block is the bundle maintainer's own comments: strings in the file,
        # so naming a certificate with them is not parsing one. The fingerprint line is an independent
        # check on this script's hashing: if the stated SHA-256 of DER equals the SHA-256 computed here,
        # the PEM split and base64 decode are right for that certificate, and 120 of them agreeing tests
        # the collector in a way no fixture-based unit test can.
        subject, alias, bare, fingerprint = None, None, None, None
        for line in reversed(header.splitlines()):
            stripped = line.strip().lstrip("#").strip()
            low = stripped.lower()
            if "-----" in stripped:
                # Any boundary-looking line -- a stray delimiter, a lowercase `-----begin` that is not a
                # block -- ends the region: what lies above it belongs to something else.
                break
            if "fingerprint" in low:
                if low.startswith("sha256") and fingerprint is None:
                    fingerprint = stripped.split(":", 1)[-1].strip().replace(":", "").lower()
                continue
            # Two names, kept apart on purpose. `subject:` in a certifi header and `Owner:` in keytool output
            # are the same claim -- the holder's distinguished name, printed as a string by whoever assembled
            # the file -- while `Alias name:` in keytool output (and an archive member name, which
            # `pem_from_tar` writes as one) is a nickname. Recording an alias as a subject would name a
            # certificate something it does not say. The nearest line of each kind wins.
            if low.startswith(("subject:", "owner:")):
                if subject is None:
                    subject = stripped.split(":", 1)[1].strip() or None
                continue
            if low.startswith(("alias name:", "alias:")):
                if alias is None:
                    alias = stripped.split(":", 1)[1].strip() or None
                continue
            if (
                low.startswith(
                    (
                        "issuer:",
                        "serial:",
                        "validity:",
                        "valid from:",
                        "creation date:",
                        "entry type:",
                        "signature algorithm:",
                        "public key",
                    )
                )
                or len(stripped) < 5
            ):
                # "creation date:" and "entry type:" are JDK 26 keytool boilerplate between the alias and
                # the PEM block. Without skipping them the fallback below takes "Creation date: Nov 7, 2026"
                # as the name and stops before it ever reaches "Alias name:", which is what the first run of
                # collect_java.py did: 109 entries, every one labelled with a date.
                continue
            if bare is None and any(c.isalpha() for c in stripped):
                # A plain comment with no `key:` prefix (curl's "Name" line above its `====` rule). What it
                # is called is the caller's decision, `name_key`, and it never displaces a labelled line.
                bare = stripped
        entry: dict[str, object] = {
            "sha256": digest,
            "der_octets": len(der),
            "subject": subject,
            "alias": alias,
            "store": program,
        }
        if entry[name_key] is None:
            entry[name_key] = bare
        if fingerprint and len(fingerprint) == 64:
            entry["bundle_fingerprint_agrees"] = fingerprint == digest
        seen[digest] = entry

    counts = {
        "pem_blocks": blocks,
        "distinct_certificates": len(seen),
        "duplicate_blocks": duplicates,
        "malformed_blocks": malformed,
        "fingerprint_checked": sum(1 for c in seen.values() if "bundle_fingerprint_agrees" in c),
        "fingerprint_agrees": sum(1 for c in seen.values() if c.get("bundle_fingerprint_agrees")),
        "named": sum(1 for c in seen.values() if c.get(name_key)),
        "subject_named": sum(1 for c in seen.values() if c.get("subject")),
        "header_dumps_discarded": dumps_discarded,
        # Outside `pem_blocks` on purpose: these are not CERTIFICATE blocks, so the identity
        # distinct + duplicate + malformed == pem_blocks is untouched by them.
        "legacy_label_blocks": sum(text.count(label) for label in LEGACY_BEGINS),
    }
    return seen, counts


def pem_from_tar(payload: bytes) -> tuple[str, int, int]:
    """Concatenate the PEM spans of a gzipped tar, for stores shipped as one-anchor-per-file.

    Returns the text, how many members held a certificate, and how many carried trailing text beyond the PEM
    that was dropped. Android's AOSP bundle is exactly this shape: a directory of `<subject hash>.0` files,
    each a PEM followed by an OpenSSL text dump. Gitiles serves it as `+archive/<ref>/files.tar.gz`, so the
    store arrives as one archive instead of 140 URLs. Nothing here parses a certificate: the archive is a
    container for PEM, and `index_pem` still does the only hashing in the program.
    """
    import tarfile

    text: list[str] = []
    members = 0
    dumped = 0
    end_marker = "-----END CERTIFICATE-----"
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.lower()
            if not (name.endswith(".pem") or name.endswith(".0") or name.endswith(".crt")):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            chunk = handle.read().decode("utf-8", errors="replace")
            blocks = 0
            while "-----BEGIN CERTIFICATE-----" in chunk:
                start = chunk.index("-----BEGIN CERTIFICATE-----")
                stop = chunk.find(end_marker, start)
                if stop < 0:
                    break
                pem = chunk[start : stop + len(end_marker)] + "\n"
                if blocks == 0:
                    # AOSP filenames are OpenSSL subject hashes (`0a775be3.0`): an identifier, not a
                    # distinguished name, so it goes in the alias field the way keytool's does.
                    text.append(f"Alias name: {member.name}\n{pem}")
                else:
                    text.append(pem)
                blocks += 1
                chunk = chunk[stop + len(end_marker) :]
            if blocks == 0:
                continue
            if chunk.strip():
                # AOSP ships more than PEM: each file appends an OpenSSL `Certificate:` text dump whose
                # `Subject:` line describes the certificate it sits under. Left in place, that line is the
                # last text before the next BEGIN marker, so the label walk hands certificate N's subject to
                # certificate N+1. Measured: 148 of 149 Android names were wrong this way, while every digest
                # was right, because digests never look at the text -- which is exactly how it hid. Only the
                # PEM spans are kept; the count of dropped dumps is recorded in provenance.
                dumped += 1
            members += 1
    return "\n".join(text), members, dumped


def retained_digests(path: Path, *, program: str, name_key: str, tar: bool = False) -> set[str]:
    """The certificate digest set that the retained file at `path` indexes to, read the way it was read.

    The retained copy under `raw/` is what `check_spki_artifact.py` derives SPKI digests from, so it must be
    the very text this run hashed and not merely the same source. Re-indexing it here, with the same reader
    (`pem_from_tar` for an archive, UTF-8 with replacement otherwise) and the same `index_pem`, is the check
    that the copy and the artifact describe one trust set.
    """
    payload = path.read_bytes()
    if tar:
        text = pem_from_tar(payload)[0]
    else:
        # Decoded exactly as `Path.read_text` decodes a `--path` file (UTF-8 with replacement, universal
        # newlines), so a retained CRLF file re-indexes the way its source was indexed.
        text = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8", errors="replace").read()
    seen, _ = index_pem(text, program=program, name_key=name_key)
    return set(seen)


def membership_change(previous: Path, program: str, current: Iterable[str]) -> dict[str, object]:
    """What changed in `program`'s membership since the artifact at `previous`, by SHA-256 of DER.

    The artifact path is keyed by program alone, so a run writes over the one before it. Diffing first
    keeps that overwrite from erasing what the program used to trust: the superseded file is named by its
    own SHA-256 and `retrieved_at`, and its digest set is recoverable as current - added + removed. A first
    run says so (`previous: None`) rather than reporting every anchor as added, which would read as a
    program that grew from nothing. A previous file that cannot be read as an artifact of this program is
    recorded as `comparable: false` with the reason, never diffed as if it were empty.
    """
    now = set(current)
    if not previous.is_file():
        return {
            "previous": None,
            "note": f"first run: no previous artifact for {program!r} at {previous}",
        }
    raw = previous.read_bytes()
    before: dict[str, object] = {
        "path": str(previous),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }
    try:
        old = json.loads(raw.decode("utf-8"))
        before["retrieved_at"] = old.get("retrieved_at")
        before["program"] = old.get("program")
        then = {str(row["sha256"]) for row in old["certificates"]}
    except (UnicodeDecodeError, ValueError, AttributeError, KeyError, TypeError) as exc:
        return {
            "previous": before,
            "comparable": False,
            "reason": f"previous artifact unreadable: {type(exc).__name__}: {exc}"[:300],
        }
    if before["program"] != program:
        return {
            "previous": before,
            "comparable": False,
            "reason": f"previous artifact is for program {before['program']!r}, not {program!r}",
        }
    before["distinct_certificates"] = len(then)
    added, removed = sorted(now - then), sorted(then - now)
    return {
        "previous": before,
        "comparable": True,
        "counts": {"added": len(added), "removed": len(removed), "unchanged": len(now & then)},
        "added": added,
        "removed": removed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument("--program", default="certifi")
    parser.add_argument("--path", default=None, help="PEM bundle to read instead of a default")
    parser.add_argument(
        "--url",
        default=None,
        help="fetch this PEM bundle instead (the image has no certifi package and will not grow one)",
    )
    parser.add_argument(
        "--tar",
        action="store_true",
        help="the --url payload is a gzipped archive of one-anchor-per-file (Android's AOSP bundle)",
    )
    parser.add_argument(
        "--reader",
        default=None,
        help="an executable that prints PEM on stdout -- the store's OWN reader (keytool, node, "
        "python -c), which is how this file avoids implementing anyone's trust format",
    )
    parser.add_argument(
        "--reader-arg",
        action="append",
        default=[],
        dest="reader_args",
        help="argument for --reader, repeated, and always written --reader-arg=VALUE: argparse refuses "
        "a separate value that begins with '-' (--reader-arg -c fails on 3.12 and later alike), so "
        "--reader-arg=-c is the only spelling that reaches the reader. Passed as argv, never through a shell.",
    )
    parser.add_argument(
        "--reader-name-key",
        default="subject",
        choices=NAME_KEYS,
        dest="reader_name_key",
        help='what to call an unkeyed comment line above a block: "alias" for keytool nicknames',
    )
    args = parser.parse_args()

    # Three sources, one hasher. A store is only comparable with another store if both digests come
    # from the same code, which is why readers reuse index_pem rather than shipping their own split.
    if args.reader:
        argv = [args.reader, *args.reader_args]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=300)  # noqa: S603
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"reader could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if done.returncode != 0:
            detail = (done.stderr or done.stdout).strip()[:300]
            print(f"reader {argv[0]} exited {done.returncode}: {detail}", file=sys.stderr)
            print(
                "A reader that will not speak is a fact about the host; nothing was written.",
                file=sys.stderr,
            )
            return 1
        text = done.stdout
        # The reader's stdout is retained exactly as it was indexed, so the PEM a reader printed once can be
        # read again without re-running the reader on a host whose store may have moved since.
        retain = text.encode("utf-8", "replace")
        origin: dict[str, object] = {
            "reader": argv,
            "reader_stderr": (done.stderr or "").strip()[:400],
            "pem_sha256": hashlib.sha256(retain).hexdigest(),
            "method": (
                f"asked the store's own reader ({argv[0]}) for PEM on stdout, then "
                "collect_bundle.index_pem: split CERTIFICATE blocks, base64-decode, SHA-256 the DER"
            ),
        }
    elif args.url:
        raw_dir = Path(args.data) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        path = raw_dir / (f"{args.program}.tar.gz" if args.tar else f"{args.program}.pem")
        payload = urllib.request.urlopen(  # noqa: S310
            urllib.request.Request(args.url, headers={"User-Agent": UA}),  # noqa: S310
            timeout=90.0,
            context=ssl.create_default_context(),
        ).read(32 * 1024 * 1024 + 1)
        path.write_bytes(payload)
        if args.tar:
            text, members, dumped = pem_from_tar(payload)
            origin_extra = {
                "archive_members_with_pem": members,
                "trailing_text_dumps_dropped": dumped,
                "method": (
                    "fetched a gzipped archive, kept only the PEM spans of its members (one anchor per "
                    "file, with any trailing OpenSSL text dump dropped), then "
                    "collect_bundle.index_pem: split CERTIFICATE blocks, base64-decode, SHA-256 the DER"
                ),
            }
        else:
            text = payload.decode("utf-8", errors="replace")
            origin_extra = {
                "method": "split PEM CERTIFICATE blocks, base64-decode, SHA-256 the DER"
            }
        origin = {
            "url": args.url,
            "cached_at": str(path),
            "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            **origin_extra,
        }
    else:
        local = bundle_path(args.program, args.path)
        if local is None or not local.is_file():
            print(f"no bundle at {local}", file=sys.stderr)
            return 1
        retain = local.read_bytes()
        text = local.read_text(encoding="utf-8", errors="replace")
        origin = {
            "path": str(local),
            "file_sha256": hashlib.sha256(retain).hexdigest(),
            "method": "split PEM CERTIFICATE blocks, base64-decode, SHA-256 the DER",
        }

    seen, counts = index_pem(text, program=args.program, name_key=args.reader_name_key)

    # Every mode leaves the bytes it indexed under raw/, named as --url names them, so a later reader (the
    # SPKI check) works from what was hashed. --path and --reader write beside the final name and move into
    # place only once the copy re-indexes to this run's digest set; a copy that does not is refused along
    # with the artifact, rather than left to describe a trust set the artifact does not hold.
    if args.url:
        retained = Path(str(origin["cached_at"]))
        staged = None
    else:
        retained = Path(args.data) / "raw" / f"{args.program}.pem"
        retained.parent.mkdir(parents=True, exist_ok=True)
        staged = retained.with_name(retained.name + ".partial")
        staged.write_bytes(retain)
        origin["cached_at"] = str(retained)
        origin["file_sha256"] = hashlib.sha256(staged.read_bytes()).hexdigest()
    again = retained_digests(
        staged or retained,
        program=args.program,
        name_key=args.reader_name_key,
        tar=bool(args.url and args.tar),
    )
    if again != set(seen):
        if staged is not None:
            staged.unlink()
        print(
            f"retained copy {retained} re-indexes to {len(again)} digests, not this run's "
            f"{len(seen)} ({len(again ^ set(seen))} differ); no artifact was written",
            file=sys.stderr,
        )
        return 1
    if staged is not None:
        os.replace(staged, retained)

    out = Path(args.data) / "store" / f"{args.program}.json"
    change = membership_change(out, args.program, seen)

    doc = {
        "artifact": "trustatlas.bundle.collect",
        "version": 1,
        "program": args.program,
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "provenance": {
            **origin,
            "note": (
                "hashes and counts only: no subject, no SPKI, no validity. A certificate's identity"
                " here is its SHA-256 of DER, which cannot connect two certificates that share a key."
            ),
        },
        "counts": counts,
        "membership_change": change,
        "certificates": sorted(seen.values(), key=lambda c: str(c["sha256"])),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))
    print(
        f"{args.program}: {counts['pem_blocks']} PEM blocks, "
        f"{counts['distinct_certificates']} distinct certificates, "
        f"{counts['duplicate_blocks']} duplicate"
        f"{'s' if counts['duplicate_blocks'] != 1 else ''}, "
        f"{counts['malformed_blocks']} malformed -> {out}"
    )
    checks = doc["counts"]
    print(
        f"  the bundle states a SHA-256 for {checks['fingerprint_checked']} certificates; "
        f"{checks['fingerprint_agrees']} match what this script hashed, and "
        f"{checks['named']} carry a name in the file"
    )
    if counts["legacy_label_blocks"]:
        print(
            f"warning: {counts['legacy_label_blocks']} block(s) carry the legacy 'X509 CERTIFICATE' or "
            "'X.509 CERTIFICATE' label (RFC 7468 section 5.1); counted in legacy_label_blocks, not hashed",
            file=sys.stderr,
        )
    if change["previous"] is None:
        print("  no previous artifact for this program: membership not diffed (first run)")
    elif change.get("comparable"):
        moved = change["counts"]
        assert isinstance(moved, dict)
        print(
            f"  against the previous artifact: {moved['added']} added, {moved['removed']} removed, "
            f"{moved['unchanged']} unchanged"
        )
    else:
        print(f"  previous artifact not compared: {change['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
