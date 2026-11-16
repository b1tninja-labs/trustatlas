"""Read a JDK trust store as an artifact, letting Java interpret its own keystore format.

The last unread program of the ones `ta.readers_remaining` names that this machine actually holds:
`<jdk>/lib/security/cacerts`. `PLAN.md` claims Java's cacerts descends from Mozilla's NSS built-ins
alongside curl, certifi and Debian; until this file ran, that claim was documentation.

Why it shells out instead of parsing. A PKCS12 keystore is a container with an encrypted inner
PKCS#7 blob, and writing a reader for it here would create exactly the second, laxer PKI
implementation `AGENTS.md` forbids. `keytool` is Java's own reader, so the keystore format stays
Java's business and this script does only what `collect_bundle.py` already does: take PEM blocks,
base64-decode, SHA-256 the DER. It imports that function rather than copying it, because the value of
the join depends on every program's digest coming from one implementation.

Naming is deliberately modest. `keytool -list -rfc` puts an *alias* where a curl comment block puts a
`subject:`, and an alias is a nickname the keystore chose, not a distinguished name. It is recorded
under `alias` and `subject` stays absent, so the joiner treats this side as hash-only the way it treats
every other bundle.

The PEM keytool printed is retained, byte for byte, as `raw/<program>.pem` under `--data`, with its path,
SHA-256 and octet count in the provenance (`raw`, `raw_sha256`, `raw_octets`), so `check_spki_artifact.py`
can hand it to asn1core for SPKI digests. The retained file is re-indexed from disk before anything is kept;
if it does not reproduce the artifact's certificate digest set, nothing is written and the exit is non-zero.
The storepass is never retained: keytool does not echo it, and output that carries it is refused.

Usage:
    python tools/collect_java.py --data M:\\trustatlas
    python tools/collect_java.py --keystore "C:\\path\\to\\jdk\\lib\\security\\cacerts"
"""

from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import json
import locale
import os
import platform
import subprocess
import sys
from pathlib import Path

from collect_bundle import index_pem

DEFAULT_PROGRAM = "java.cacerts"
DEFAULT_STOREPASS = "changeit"
# What `subprocess.run(..., text=True)` decodes a child's output with, which is what this file used to rely on.
STDOUT_ENCODING = locale.getpreferredencoding(False)
# Where a JDK keeps cacerts, in the order a reader would look. Oracle's Windows `javapath` directory is
# deliberately absent: it holds a java.exe stub and no lib/, so it is not a JDK root.
SEARCH_GLOBS = (
    r"C:\Program Files\Java\jdk-*\lib\security\cacerts",
    r"C:\Program Files\Eclipse Adoptium\jdk-*\lib\security\cacerts",
    r"C:\Program Files\Microsoft\jdk-*\lib\security\cacerts",
    r"C:\Program Files\Amazon Corretto\jdk*\lib\security\cacerts",
    r"C:\Program Files\Zulu\zulu-*\lib\security\cacerts",
    "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts",
    "/usr/lib/jvm/*/lib/security/cacerts",
    "/etc/pki/java/cacerts",
)


def find_keystore(explicit: str | None) -> tuple[Path | None, list[str]]:
    """The keystore to read, plus every place looked. The list is provenance, not debug output."""
    looked: list[str] = []
    if explicit:
        looked.append(f"--keystore {explicit}")
        path = Path(explicit)
        return (path if path.is_file() else None), looked
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        path = Path(java_home) / "lib" / "security" / "cacerts"
        looked.append(f"{path} (JAVA_HOME)")
        if path.is_file():
            return path, looked
    for pattern in SEARCH_GLOBS:
        looked.append(pattern)
        for candidate in sorted(glob.glob(pattern)):
            path = Path(candidate)
            if path.is_file():
                return path, looked
    return None, looked


def keytool_path(keystore: Path) -> Path | None:
    """<jdk>/bin/keytool, derived from where the keystore was found rather than from PATH."""
    jdk = keystore.parent.parent.parent  # <jdk>/lib/security/cacerts
    for name in ("keytool.exe", "keytool"):
        candidate = jdk / "bin" / name
        if candidate.is_file():
            return candidate
    return None


def jdk_version(jdk_bin: Path) -> str:
    """Whatever `java -version` reports, which the JDK has always written to stderr."""
    for name in ("java.exe", "java"):
        candidate = jdk_bin / name
        if not candidate.is_file():
            continue
        try:
            done = subprocess.run(  # noqa: S603 - path derived from the keystore, not from user text
                [str(candidate), "-version"], capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"unavailable ({type(exc).__name__})"
        text = (done.stderr or done.stdout).strip()
        return text.splitlines()[0] if text else "no output"
    return "no java beside keytool"


def as_text(payload: bytes) -> str:
    """Decode keytool's output the way `subprocess.run(..., text=True)` would: locale encoding, universal newlines."""
    return payload.decode(STDOUT_ENCODING).replace("\r\n", "\n").replace("\r", "\n")


def read_retained(path: Path) -> bytes:
    """The retained PEM as read back from disk. A seam on purpose: the re-index check reads through it."""
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument("--program", default=DEFAULT_PROGRAM)
    parser.add_argument("--keystore", default=None, help="cacerts path; discovered if omitted")
    parser.add_argument(
        "--storepass",
        default=DEFAULT_STOREPASS,
        help="the JDK's published default: this reads a public trust store, not a private one",
    )
    args = parser.parse_args()

    keystore, looked = find_keystore(args.keystore)
    if keystore is None:
        print("no JDK trust store found. Looked at:", file=sys.stderr)
        for entry in looked:
            print(f"  {entry}", file=sys.stderr)
        print("Pass --keystore or set JAVA_HOME. Nothing was written.", file=sys.stderr)
        return 3

    keytool = keytool_path(keystore)
    if keytool is None:
        print(f"no keytool beside {keystore}", file=sys.stderr)
        return 3

    command = [
        str(keytool),
        "-list",
        "-rfc",
        "-keystore",
        str(keystore),
        "-storepass",
        args.storepass,
    ]
    try:
        # Bytes, not text mode: the retained file is what keytool wrote, byte for byte. `as_text` then
        # applies the same decode-and-newline step text mode would have, so the index is unchanged.
        done = subprocess.run(command, capture_output=True, timeout=180)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"keytool could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    stdout_bytes: bytes = done.stdout or b""
    stderr_text = as_text(done.stderr or b"")
    if done.returncode != 0:
        detail = (stderr_text or as_text(stdout_bytes)).strip()[:400]
        print(f"keytool exited {done.returncode}: {detail}", file=sys.stderr)
        print("A keystore that will not open is a fact about the host.", file=sys.stderr)
        return 1
    if args.storepass and args.storepass.encode(STDOUT_ENCODING) in stdout_bytes:
        # keytool does not echo the storepass; if this output carries it, retaining it would publish it.
        print(
            "keytool output contains the storepass; refusing to retain it. Nothing was written.",
            file=sys.stderr,
        )
        return 1

    raw = keystore.read_bytes()
    seen, counts = index_pem(as_text(stdout_bytes), program=args.program, name_key="alias")

    # Retain the PEM as keytool printed it, so asn1core can re-derive SPKI from it later
    # (`check_spki_artifact.py`). It is written beside its final name first and re-indexed from disk: if what
    # was retained does not reproduce the digest set this artifact lists, neither file is written.
    raw_path = Path(args.data) / "raw" / f"{args.program}.pem"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    pending = raw_path.with_name(raw_path.name + ".partial")
    pending.write_bytes(stdout_bytes)
    retained = read_retained(pending)
    again, _ = index_pem(as_text(retained), program=args.program, name_key="alias")
    if retained != stdout_bytes or set(again) != set(seen):
        pending.unlink(missing_ok=True)
        print(
            f"re-indexing the retained PEM gave {len(again)} certificates, the artifact lists {len(seen)}"
            f" ({len(set(again) ^ set(seen))} differ). Nothing was written.",
            file=sys.stderr,
        )
        return 1
    os.replace(pending, raw_path)

    doc = {
        "artifact": "trustatlas.bundle.collect",
        "version": 1,
        "program": args.program,
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "provenance": {
            "keystore": str(keystore),
            "keystore_sha256": hashlib.sha256(raw).hexdigest(),
            "keystore_octets": len(raw),
            "reader": str(keytool),
            "jdk_version": jdk_version(keytool.parent),
            "command": " ".join([*command[:4], "<keystore>", "<storepass>"]),
            "method": (
                "keytool -list -rfc (Java's own keystore reader) to PEM, then the shared "
                "collect_bundle.index_pem: split CERTIFICATE blocks, base64-decode, SHA-256 the DER"
            ),
            "host": f"{platform.system()}-{platform.release()}-{platform.machine()}",
            "keytool_stderr": stderr_text.strip()[:600],
            "raw": str(raw_path),
            "raw_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "raw_octets": len(stdout_bytes),
            "raw_form": (
                f"keytool -list -rfc stdout, byte for byte; indexed after decoding as {STDOUT_ENCODING} "
                "with newlines normalised, as text mode would"
            ),
            "raw_reindex": {
                "check": "re-read the retained file and re-ran index_pem; the digest set must equal this artifact's",
                "distinct_certificates": len(again),
                "agrees": True,
            },
            "looked": looked,
            "note": (
                "hashes and counts only, and the name carried is the keystore's alias, not a subject. "
                "No PKI is implemented here: the keystore format stays Java's, and what this reads is PEM."
            ),
        },
        "counts": counts,
        "certificates": sorted(seen.values(), key=lambda c: str(c["sha256"])),
    }
    out = Path(args.data) / "store" / f"{args.program}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))

    print(
        f"{args.program}: {counts['pem_blocks']} PEM blocks, "
        f"{counts['distinct_certificates']} distinct certificates, "
        f"{counts['duplicate_blocks']} duplicate, {counts['malformed_blocks']} malformed -> {out}"
    )
    print(f"  read by {keytool.name} from {doc['provenance']['jdk_version']}")
    print(
        f"  {counts['named']} carry an alias and none carries a subject: a join can name this side by "
        "keystore nickname, but not by distinguished name (that would need -v, and Owner: is Java's word "
        "for the subject, not this file's claim)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
