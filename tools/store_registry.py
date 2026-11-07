"""The registry of trust stores: where each program keeps its anchors, and whose reader says so.

A trust map that must be told about a store every time it measures one never covers anything. This is the
codified answer to "where do the roots come from, for THIS client, on THIS OS": one row per store, naming its
location, the reader that can print it without this repository implementing anyone's PKI, where its contents
came from, and how sure we are. `--probe` reads the table against the host it runs on and writes
`store/registry.status.json`: present or not, whose version, when the file or binary last changed, how many
anchors the last artifact counted and when that was taken. That artifact is what a surface would render. It is
not a live oracle: it states what it saw, when, on which machine.

Three honesty rules the table has to keep, because this week's measurements broke each of them:

* **A client is not a store.** Chrome and Edge on Windows consult the Windows store; on macOS and iOS they
  consult Security.framework; on Linux, NSS. Counting twelve clients as twelve stores would describe one
  machine's roots twelve times. Rows name the store; `clients` records who reads it.
* **Bundled is not derived.** Node compiles a Mozilla-derived set into its binary; Java's cacerts is Mozilla's
  list plus Oracle's decisions. `origin` carries that; `confidence` says whether it is measured here,
  documented upstream, or guessed.
* **A row can be wrong in a way that matters.** `python.schannel` exists because Python's own default context
  disagrees with the OS's listing of the same hive by 18 certificates, 6 of them issuing CAs rather than
  anchors. A row reading "Python: see Windows store" would hide that.

Usage:
    python tools/store_registry.py --probe --data M:\\trustatlas
    python tools/store_registry.py --list
    python tools/store_registry.py --show python.schannel
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

# MEASURED: read on this host by the reader named, artifact present. DOCUMENTED: upstream says where it lives,
# nobody here has opened it. GUESSED: plausible location, kept visible so the next person tests it.
MEASURED, DOCUMENTED, GUESSED = "measured", "documented", "guessed"

REGISTRY: tuple[dict[str, Any], ...] = (
    {
        "id": "windows.root.machine",
        "kind": "os-store",
        "os": ("windows",),
        "location": r"Cert:\LocalMachine\Root",
        "reader": ["collect_store.py", "--location", "LocalMachine", "--store", "Root"],
        "origin": "Microsoft Trusted Root Program (authroot.stl), installed by Windows Update",
        "artifact": "windows.machine.json",
        "clients": ("Chrome/Edge on Windows", "Schannel", ".NET X509Store", "WinHTTP"),
        "confidence": MEASURED,
        "note": "68 anchors here. PowerShell's certificate provider is the reader, so every field is Windows' own statement about an anchor.",
    },
    {
        "id": "windows.root.user",
        "kind": "os-store",
        "os": ("windows",),
        "location": r"Cert:\CurrentUser\Root",
        "reader": ["collect_store.py", "--location", "CurrentUser", "--store", "Root"],
        "origin": "added by the user, or by an installer running as that user; not machine-wide",
        "artifact": "windows.user.json",
        "clients": ("the same clients, for this user only",),
        "confidence": MEASURED,
        "note": "The one an incident needs: a user-installed root silently outranks every program policy for that user. Measured byte-identical to the machine store here (68), so nothing is user-installed on this host -- a measured negative, not an assumption.",
    },
    {
        "id": "windows.authroot.machine",
        "kind": "os-store",
        "os": ("windows",),
        "location": r"Cert:\LocalMachine\AuthRoot",
        "reader": ["collect_store.py", "--store", "AuthRoot"],
        "origin": "cross-signed intermediate copies letting an old chain reach a new root",
        "artifact": "windows.machine.json",
        "clients": ("Chrome/Edge on Windows", "Schannel"),
        "confidence": MEASURED,
        "note": "52 entries. Where cross-signing lives on Windows, and why retiring a root can go unnoticed by clients holding the twin.",
    },
    {
        "id": "windows.disallowed",
        "kind": "os-store",
        "os": ("windows",),
        "location": r"Cert:\LocalMachine\Disallowed",
        "reader": ["collect_store.py", "--store", "Disallowed"],
        "origin": "the local half of a revocation decision, normally empty",
        "artifact": "windows.machine.json",
        "clients": ("Schannel", "code signing"),
        "confidence": MEASURED,
        "note": "0 here, which is the fact the eMudhra-era guidance asks a user to establish from a browser error page.",
    },
    {
        "id": "python.schannel",
        "kind": "runtime-effective",
        "os": ("windows",),
        "location": "whatever ssl.create_default_context() actually loaded",
        "reader": [
            "collect_bundle.py",
            "--program",
            "python.schannel",
            "--reader",
            "py",
            "--reader-arg",
            "-c",
            "--reader-arg",
            "<emit # Subject: + PEM from get_ca_certs()>",
        ],
        "origin": "the OS store as crypt32 enumerates it, narrowed by purpose",
        "artifact": "python.schannel.json",
        "clients": ("CPython stdlib ssl", "pip", "requests", "httpx"),
        "confidence": MEASURED,
        "note": "72 anchors where PowerShell lists 68 in the same hive; 54 shared. The 14 Python omits are code-signing and time-stamping roots. The 18 it adds are not anchors by any reading: RapidSSL TLS RSA CA G1, GoDaddy TLS Intermediate CA DV - R1v1, Microsoft Update Secure Server CA 2.1, Microsoft Secure Server CA 2011, Microsoft Code Signing PCA 2024, a Microsoft TLS OCSP responder. Mechanism unresolved; consequence is not.",
    },
    {
        "id": "node.bundled",
        "kind": "bundled",
        "os": ("windows", "linux", "macos"),
        "location": "compiled into the node binary (CA_ROOT_CERT), a Mozilla-derived set",
        "reader": [
            "node",
            "-e",
            "console.log(require('tls').rootCertificates.join('\\n'))",
        ],
        "origin": "Mozilla's list as of the binary's build",
        "artifact": "node.bundled.json",
        "clients": ("Node", "npm", "yarn", "anything running on Node"),
        "confidence": MEASURED,
        "note": "145 anchors; certifi's 120 are a strict subset of them, which is a measured derivation edge rather than a documentation claim. Node ignores the OS store unless --use-openssl-ca is passed, so a root revoked at the OS never reaches a Node client.",
    },
    {
        "id": "java.cacerts",
        "kind": "runtime-store",
        "os": ("windows", "linux", "macos"),
        "location": "<JAVA_HOME>/lib/security/cacerts",
        "reader": ["collect_java.py"],
        "origin": "Mozilla's list plus Oracle's own inclusions and retentions",
        "artifact": "java.cacerts.json",
        "clients": ("JVM clients that do not override trust", "SDK tooling"),
        "confidence": MEASURED,
        "note": "109 anchors; 50 are not trusted for TLS by Mozilla at all, mostly retired vendor roots (VeriSign Universal, GeoTrust primary x2, Thawte primary) plus Korean national roots. keytool reads it, so Java's container format stays Java's business.",
    },
    {
        "id": "certifi",
        "kind": "program-list",
        "os": ("any",),
        "location": "certifi.where() -- a package data file",
        "reader": ["collect_bundle.py", "--program", "certifi"],
        "origin": "Mozilla's list, republished as a Python package",
        "artifact": "certifi.json",
        "clients": ("requests", "httpx", "pip when certifi is used"),
        "confidence": MEASURED,
        "note": "120 anchors. Each block carries a '# Subject:' and a stated SHA-256, which lets the collector check its own hashing against the maintainer's numbers.",
    },
    {
        "id": "curl.mozilla_bundle",
        "kind": "program-list",
        "os": ("any",),
        "location": "https://curl.se/ca/cacert.pem",
        "reader": ["collect_bundle.py", "--url", "https://curl.se/ca/cacert.pem"],
        "origin": "Mozilla's list, converted to PEM",
        "artifact": "curl.json",
        "clients": (
            "curl --cacert",
            "wget",
            "OpenSSL builds pointed at it",
            "countless appliances",
        ),
        "confidence": MEASURED,
        "note": "118 anchors and no names in the file at all: a bundle's side of a difference can be counted but not named unless a comment header is present.",
    },
    {
        "id": "mozilla.nss.certdata",
        "kind": "program-source",
        "os": ("any",),
        "location": "security/nss/lib/ckfw/builtins/certdata.txt in mozilla-central",
        "reader": ["collect_certdata.py"],
        "origin": "the upstream source of nearly every row above",
        "artifact": "mozilla.nss.json",
        "clients": (
            "Firefox",
            "Chrome and Edge on Linux",
            "Thunderbird",
            "anything built on NSS",
        ),
        "confidence": MEASURED,
        "note": "169 objects, 117 of them TLS-delegating. The trust bits are why it cannot be compared with a TLS-only store unfiltered: NSS-169 against Java-109 reports 93 anchors Java 'lacks' that NSS keeps only for S/MIME or code signing.",
    },
    {
        "id": "android.aosp",
        "kind": "os-store",
        "os": ("android",),
        "location": "platform/system/ca-certificates/files -- one PEM per anchor, filename is the subject hash",
        "reader": [
            "collect_bundle.py",
            "--url",
            "<AOSP gitiles archive, URL not yet fixed>",
        ],
        "origin": "Mozilla's list as shipped in the AOSP branch; OEMs add their own anchors",
        "artifact": None,
        "clients": ("Android platform via Conscrypt",),
        "confidence": DOCUMENTED,
        "note": "Catalogued reachable (status 200) but the URL probed was an HTML directory, so stable:false: not an artifact until a fixed file or archive URL is chosen. Android also keeps per-user and per-work-profile stores, which is why 'Android trusts X' has no single answer. Source of the guidance that disabling AAA Certificate Services may break unrelated sites.",
    },
    {
        "id": "apple.security.framework",
        "kind": "os-store",
        "os": ("macos", "ios"),
        "location": "anchors built into the OS; admin overrides in the keychain, exportable with security trust-settings-export",
        "reader": ["security", "trust-settings-export"],
        "origin": "Apple's own program",
        "artifact": None,
        "clients": (
            "Safari",
            "CFNetwork",
            "Chrome on macOS/iOS",
            "Edge on macOS/iOS",
            "Network.framework",
        ),
        "confidence": DOCUMENTED,
        "note": "Not measurable from a Windows host -- needs a Mac. Apple publishes a program page rather than a machine-readable anchor list, and its roots live inside the OS image. Marked unread rather than guessed at: an anchor set is verified by observation, not by reading the docs.",
    },
    {
        "id": "debian.ca_certificates",
        "kind": "distro-bundle",
        "os": ("linux",),
        "location": "/etc/ssl/certs/ca-certificates.crt, generated by update-ca-certificates",
        "reader": ["collect_bundle.py", "--url", "<salsa.debian.org listing>"],
        "origin": "Mozilla's list, packaged; local PEMs an admin drops in are folded in",
        "artifact": None,
        "clients": (
            "OpenSSL on Debian/Ubuntu",
            "GnuTLS",
            "wget",
            "most Linux interpreters",
        ),
        "confidence": DOCUMENTED,
        "note": "The Linux answer to 'what does the OS trust' is a generated file plus its hash, which is why the artifact is the bundle and its digest rather than a claim about an OS store.",
    },
    {
        "id": "redhat.p11kit",
        "kind": "distro-bundle",
        "os": ("linux",),
        "location": "/etc/pki/tls/certs/ca-bundle.crt via update-ca-trust and the p11-kit trust store",
        "reader": ["trust", "list-anchors"],
        "origin": "Mozilla's list via the distribution, plus admin-anchored additions",
        "artifact": None,
        "clients": ("OpenSSL and GnuTLS on RHEL/Fedora", "systemd-resolved", "sssd"),
        "confidence": DOCUMENTED,
        "note": "p11-kit is the closest thing Linux has to an OS-level anchor registry, and it is per-distro. Unreachable from this host.",
    },
    {
        "id": "openssl.default",
        "kind": "crypto-module",
        "os": ("any",),
        "location": "`openssl version -d` gives OPENSSLDIR; SSL_CERT_FILE and SSL_CERT_DIR override it",
        "reader": ["openssl", "version", "-d"],
        "origin": "whatever the build or the admin pointed it at -- the distro bundle on Linux, often nothing on Windows",
        "artifact": None,
        "clients": (
            "openssl s_client",
            "libssl users",
            "curl built against system OpenSSL",
        ),
        "confidence": DOCUMENTED,
        "note": "Less a store than a pointer to one, and the two environment variables are how two programs on one machine disagree. The registry records the pointer; the artifact records what it pointed at that day. This host has OpenSSL 3.0.18 only as a library inside Python, with no openssl.exe to ask.",
    },
    {
        "id": "dotnet.x509store",
        "kind": "runtime-effective",
        "os": ("windows", "linux", "macos"),
        "location": "X509Store(StoreName.Root) on Windows; OpenSSL-backed elsewhere with an OS-store fallback",
        "reader": ["dotnet", "(probe not written)"],
        "origin": "the OS store, plus per-app trust overrides",
        "artifact": None,
        "clients": ("HttpClient", "ASP.NET", "Azure SDK", "PowerShell"),
        "confidence": GUESSED,
        "note": ".NET's cross-platform trust behaviour has changed more than once, so this location is a placeholder that says so. A row marked guessed exists to be tested, not to be cited.",
    },
    {
        "id": "go.systemcertpool",
        "kind": "runtime-effective",
        "os": ("windows", "linux", "macos"),
        "location": "x509.SystemCertPool(): the Windows store, the macOS keychain, or a searched list of Linux bundle paths",
        "reader": ["go", "run probe.go"],
        "origin": "the OS store where one exists, otherwise the distro bundle",
        "artifact": None,
        "clients": ("Go stdlib net/http", "kubectl", "most cloud CLIs"),
        "confidence": GUESSED,
        "note": "Go ships its own X.509 parser rather than calling the platform's, so 'Go trusts X' can differ from 'the OS lists X' for parsing reasons alone. No Go toolchain on this host, so unmeasured.",
    },
    {
        "id": "rust.webpki_roots",
        "kind": "bundled",
        "os": ("any",),
        "location": "the webpki-roots crate (Mozilla-derived, compiled in); rustls-native-certs reads the OS store instead",
        "reader": ["cargo", "(probe not written)"],
        "origin": "Mozilla's list, vendored at a crate version",
        "artifact": None,
        "clients": ("reqwest with rustls", "ureq", "container runtimes"),
        "confidence": DOCUMENTED,
        "note": "A binary here can be rebuilt against a newer crate without the operator noticing, so 'last updated' is a crate version rather than a file mtime -- which is why the registry needs both fields.",
    },
    {
        "id": "composer.php_ca_bundle",
        "kind": "program-list",
        "os": ("any",),
        "location": "composer/ca-bundle, or the openssl.cafile php.ini directive",
        "reader": [
            "php",
            "-r",
            "echo openssl_get_cert_locations()['default_cert_file'];",
        ],
        "origin": "Mozilla's list, or the system bundle where the directive points",
        "artifact": None,
        "clients": ("PHP cURL", "Guzzle", "Composer"),
        "confidence": GUESSED,
        "note": "PHP is a large source of 'works except on one server' trust reports because the default depends on how it was built. First row worth promoting from guessed to measured.",
    },
)


def now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def host() -> str:
    return f"{platform.system()}-{platform.release()}-{platform.machine()}"


def mtime_utc(path: Path) -> str | None:
    """When the thing itself last changed: the file, or the binary a store is compiled into."""
    try:
        return datetime.datetime.fromtimestamp(
            path.stat().st_mtime, datetime.UTC
        ).isoformat(timespec="seconds")
    except OSError:
        return None


def _which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


def _version(exe: str, argv: list[str]) -> str:
    """What a tool says about itself, if it says anything quietly. Placeholder argv is skipped."""
    args = [a for a in argv if a and not a.startswith("<") and "(" not in a]
    if not args:
        return "not asked"
    try:
        done = subprocess.run([exe, *args], capture_output=True, text=True, timeout=20)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable ({type(exc).__name__})"
    out = (done.stdout or done.stderr).strip()
    return out.splitlines()[0][:120] if out else "no output"


def artifact_state(
    data: str, name: str | None, store: str | None = None
) -> dict[str, Any]:
    """What the last collection said, read from the artifact rather than remembered.

    `store` matters because several rows share one artifact: Root, AuthRoot and Disallowed all live in
    `windows.machine.json`, and reporting that file's total of 68 against each of them claimed Disallowed held
    68 anchors when it holds none. The per-store figure is taken from the artifact's own counts.
    """
    if not name:
        return {"collected": False, "reason": "registry row names no artifact yet"}
    path = Path(data) / "store" / name
    if not path.is_file():
        return {"collected": False, "reason": f"{path} does not exist"}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"collected": False, "reason": f"{type(exc).__name__}: {exc}"}
    counts = doc.get("counts") or {}
    per_store = counts.get("per_store") or {}
    anchors = (
        per_store.get(store)
        if store in per_store
        else counts.get("distinct_certificates")
        or counts.get("certificates")
        or counts.get("anchors")
    )
    return {
        "collected": True,
        "artifact": str(path),
        "store": store,
        "retrieved_at": doc.get("retrieved_at"),
        "program": doc.get("program"),
        "anchors": anchors,
    }


def presence(entry: dict[str, Any]) -> dict[str, Any]:
    """Whether this host can reach the store, and by what. Nothing here is taken from the docs.

    The dispatch reads the row's own reader, because a row that names a reader is testable and one that names
    only a location is not: `Cert:\\LocalMachine\\Root` is not a path and a URL is not a file.
    """
    reader = [a for a in (entry.get("reader") or [])]
    # Rows name the script as it is invoked ("collect_java.py"), so the dispatch has to compare the stem.
    # Missing that made java.cacerts report "no" on a host with a JDK installed: a registry that lies about
    # reachability is worse than no registry, because the whole point is that the table is trusted.
    head = (reader[0] if reader else "").removesuffix(".py")
    this_os = platform.system().lower()
    supported = entry.get("os") or ("any",)
    if "any" not in supported and this_os not in supported:
        return {
            "reachable": False,
            "why": f"row is for {'/'.join(supported)}; this host is {this_os}",
        }

    if head.startswith("collect_store"):
        return {
            "reachable": os.name == "nt",
            "why": "Windows certificate provider" if os.name == "nt" else "not Windows",
        }
    if head == "collect_java":
        try:
            from collect_java import find_keystore  # noqa: PLC0415 - same directory, optional by design
        except ImportError as exc:
            return {"reachable": False, "why": f"collect_java.py unreadable: {exc}"}
        keystore, _looked = find_keystore(None)
        if keystore is None:
            return {"reachable": False, "why": "no JDK trust store found on this host"}
        return {
            "reachable": True,
            "path": str(keystore),
            "last_change": mtime_utc(keystore),
            "octets": keystore.stat().st_size,
        }
    if head == "node":
        exe = _which("node")
        return {
            "reachable": exe is not None,
            "path": exe,
            "last_change": mtime_utc(Path(exe)) if exe else None,
            "why": None if exe else "node not on PATH",
        }
    if entry["id"] == "certifi":
        import importlib.util

        if importlib.util.find_spec("certifi") is None:
            return {"reachable": False, "why": "certifi not installed here"}
        try:
            import certifi  # noqa: PLC0415

            where = certifi.where()
        except Exception as exc:  # noqa: BLE001 - a broken package is a fact about the host, not a crash
            return {
                "reachable": False,
                "why": f"certifi importable but unusable: {exc}",
            }
        return {
            "reachable": Path(where).is_file(),
            "path": where,
            "last_change": mtime_utc(Path(where)),
        }
    if head in ("collect_bundle", "collect_certdata"):
        return {"reachable": True, "network": True, "why": "fetched rather than local"}
    exe = _which(head)
    if exe is None:
        return {"reachable": False, "why": f"{head!r} not on PATH"}
    return {
        "reachable": True,
        "path": exe,
        "version": _version(exe, reader[1:3]),
        "last_change": mtime_utc(Path(exe)),
    }


def _store_flag(entry: dict[str, Any]) -> str | None:
    """Which hive a row reads, taken from the argv it names rather than restated by hand."""
    argv = list(entry.get("reader") or [])
    for index, arg in enumerate(argv):
        if arg == "--store" and index + 1 < len(argv):
            return argv[index + 1]
    return None


def probe(data: str) -> list[dict[str, Any]]:
    rows = []
    for entry in REGISTRY:
        seen = presence(entry)
        rows.append(
            {
                "id": entry["id"],
                "kind": entry["kind"],
                "os": list(entry["os"]),
                "location": entry["location"],
                "origin": entry["origin"],
                "confidence": entry["confidence"],
                "clients": list(entry.get("clients") or ()),
                "reader": entry["reader"],
                "note": entry.get("note"),
                "host": seen,
                "last_collection": artifact_state(
                    data, entry.get("artifact"), _store_flag(entry)
                ),
            }
        )
    return rows


def report(rows: list[dict[str, Any]]) -> None:
    header = f"{'store':<26}{'reader':<7}{'conf':<11}{'anchors':<9}{'last change':<21}last measured"
    print(header)
    print("-" * len(header))
    for row in rows:
        host = row["host"]
        col = row["last_collection"]
        print(
            f"{row['id']:<26}"
            f"{('yes' if host.get('reachable') else 'no'):<7}"
            f"{row['confidence']:<11}"
            f"{str(col.get('anchors') if col.get('collected') else '-'):<9}"
            f"{str(host.get('last_change') or host.get('version') or '-')[:20]:<21}"
            f"{str(col.get('retrieved_at') or col.get('reason') or '-')}"
        )
    reachable = sum(1 for r in rows if r["host"].get("reachable"))
    collected = sum(1 for r in rows if r["last_collection"].get("collected"))
    print(
        f"\n{len(rows)} rows: {reachable} with a reader on this host, {collected} with an artifact. "
        "The column asks whether the reader exists, not whether the store is trustworthy; a row whose "
        "reader is present but which has no artifact is work that costs one command."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument(
        "--probe", action="store_true", help="measure the table against this host"
    )
    parser.add_argument(
        "--list", action="store_true", help="print the rows without touching the host"
    )
    parser.add_argument("--show", default=None, metavar="ID", help="one row in full")
    args = parser.parse_args()

    if args.show:
        for entry in REGISTRY:
            if entry["id"] == args.show:
                print(
                    json.dumps(
                        {**entry, "host": presence(entry)}, indent=1, default=str
                    )
                )
                return 0
        known = ", ".join(e["id"] for e in REGISTRY)
        print(f"no row {args.show!r}. Known: {known}", file=sys.stderr)
        return 2

    if args.list:
        for entry in REGISTRY:
            print(f"{entry['id']:<26} {entry['confidence']:<11} {entry['location']}")
        return 0

    rows = probe(args.data)
    report(rows)
    out_dir = Path(args.data) / "store"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"cannot write artifact: {exc}", file=sys.stderr)
        return 1
    doc = {
        "artifact": "trustatlas.registry.status",
        "version": 1,
        "probed_at": now(),
        "host": host(),
        "provenance": {
            "method": (
                "each row's own reader was asked whether it exists here (PATH lookup, keytool "
                "discovery, module import, provider call); anchor counts are read back from the "
                "artifacts, never recomputed"
            ),
            "note": (
                "Placement, not judgement: 'no' means this host cannot reach the store, not that the "
                "store does not exist. 'last change' is a file or binary mtime, which for a bundled "
                "store is the build's mtime on disk and not evidence of when its anchor list was cut."
            ),
            "registry_rows": len(rows),
            "registry_digest": hashlib.sha256(
                json.dumps([r["id"] for r in rows], sort_keys=True).encode()
            ).hexdigest()[:16],
        },
        "stores": rows,
    }
    dest = out_dir / "registry.status.json"
    dest.write_bytes((json.dumps(doc, indent=1, default=str) + "\n").encode("utf-8"))
    print(f"-> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
