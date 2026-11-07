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
import os
import platform
import subprocess
import sys
from pathlib import Path

from collect_bundle import index_pem

DEFAULT_PROGRAM = "java.cacerts"
DEFAULT_STOREPASS = "changeit"
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument("--program", default=DEFAULT_PROGRAM)
    parser.add_argument(
        "--keystore", default=None, help="cacerts path; discovered if omitted"
    )
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
        done = subprocess.run(command, capture_output=True, text=True, timeout=180)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"keytool could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip()[:400]
        print(f"keytool exited {done.returncode}: {detail}", file=sys.stderr)
        print(
            "A keystore that will not open is a fact about the host.", file=sys.stderr
        )
        return 1

    raw = keystore.read_bytes()
    seen, counts = index_pem(done.stdout, program=args.program, name_key="alias")

    doc = {
        "artifact": "trustatlas.bundle.collect",
        "version": 1,
        "program": args.program,
        "retrieved_at": datetime.datetime.now(datetime.UTC).isoformat(
            timespec="seconds"
        ),
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
            "keytool_stderr": (done.stderr or "").strip()[:600],
            "looked": looked,
            "note": (
                "hashes and counts only, and the name carried is the keystore's alias, not a subject. "
                "No PKI is implemented here: the keystore format stays Java's, and what this reads is PEM."
            ),
        },
        "counts": counts,
        "certificates": sorted(seen.values(), key=lambda c: str(c["sha256"])),  # type: ignore[arg-type]
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
