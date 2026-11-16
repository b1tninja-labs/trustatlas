"""Collect one trust program's live anchor set as an artifact: hashes and counts, no parsing.

This is `PLAN.md`'s "the most useful tool in this plan and the cheapest": reading a machine's own
trust store answers definitively and offline what the incident guidance asks a user to infer from
a browser error page. It also answers it for the cases a TLS probe cannot reach, because the store
is the fact and the probe is an inference about it.

What this script is, and is not. It runs the OS's own certificate provider and records what the OS
states about each anchor: subject, friendly name, validity window, the two hashes the OS computes,
and the enhanced-key-usage list the OS resolves. It does **not** decode a certificate. SPKI
SHA-256 — the key-level join key `PLAN.md` goal 3 wants, and the one that would connect a root to a
cross-signed copy of the same key — is `asn1core`'s obligation, not this script's; see
`PLAN.md`'s SDK table. So this artifact joins stores by *certificate* identity, and says so.

Why the default writes no certificates. `AGENTS.md`: program materials carry terms and
`cl.aup-review` has not ruled, so the posture is hashes and counts. `--with-der` opts in, for a
host you are auditing and not publishing from. It stays opt-in rather than becoming the default
because turning it on is not a neutral addition to the artifact: it asks the provider for the bytes,
sets `certificates_written` to true and adds `der_octets` to every anchor, so a default run would
change recorded fields of every store artifact collected so far, not merely add one.

What `--with-der` retains. The DER exactly as the provider returned it, one file per distinct
certificate across the stores read, at `<data>/raw/<artifact stem>/<sha256>.der` (for the default
stores of the machine hive, `raw/windows.machine/`), which is the directory shape
`asn1core/tools/collect_anchors.py --der-dir` reads. A file is written only when the SHA-256 of its
bytes equals the digest Windows stated for it, which is also its name; a certificate whose bytes and
stated digest disagree is refused, counted in `provenance.raw.refused`, and never written, and the
run exits 4 after writing the artifact. Hash-named files left in that directory by an earlier run and
not verified by this one are removed, so the directory always holds exactly this artifact's
certificates and a re-run is idempotent.

Usage:
    python tools/collect_store.py --data M:\\trustatlas
    python tools/collect_store.py --data M:\\trustatlas --with-der
    python tools/collect_store.py --store Root --store Disallowed --with-der
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import platform
import re
import subprocess  # the OS certificate store is only reachable through the OS provider
import sys
from pathlib import Path
from typing import Any

DEFAULT_STORES = ("Root", "AuthRoot", "Disallowed")
# Collectable, but not collected by default: adding CA to the default set would change what the machine
# artifact claims (its counts and every join computed from it), and CA is only interesting because one
# runtime turns its contents into trust anchors.
COLLECTABLE_STORES = (*DEFAULT_STORES, "CA", "My", "Trust")

# Ask Windows PowerShell's certificate provider for each anchor and emit one JSON object. The fields
# are what Windows computes and reports; nothing here is derived from the DER bytes themselves.
PS = r"""
$ErrorActionPreference = 'Stop'
$out = @()
foreach ($store in ($env:TA_STORES -split ',')) {
  $path = "Cert:\$($env:TA_LOCATION)\$store"
  if (-not (Test-Path $path)) { continue }
  foreach ($c in Get-ChildItem -LiteralPath $path) {
    $eku = @()
    try {
      $ext = $c.Extensions['2.5.29.37']
      if ($ext -and $ext.EnhancedKeyUsageList) {
        foreach ($u in $ext.EnhancedKeyUsageList) { $eku += @($u.CertificateExtensionId, $u.FriendlyName) }
      }
    } catch {}
    $out += [pscustomobject]@{
      store         = $store
      subject       = $c.Subject
      friendly      = $c.FriendlyName
      not_before    = $c.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssZ')
      not_after     = $c.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssZ')
      sha256        = $c.GetCertHashString('SHA256')
      sha1          = $c.GetCertHashString()
      self_signed   = ($c.Subject -eq $c.Issuer)
      eku           = $eku
      der_base64    = if ($env:TA_WITH_DER) { [Convert]::ToBase64String($c.RawData) } else { $null }
    }
  }
}
# -Depth is explicit because the default is 2, which serialises a nested array as "System.Object[]":
# the EKU list would silently become a string, and "no anchor carries an EKU" would then be an
# artifact of the serializer rather than a fact about the store.
ConvertTo-Json -Compress -Depth 6 -InputObject @($out)
"""


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def read_store(
    stores: list[str], with_der: bool, location: str = "LocalMachine"
) -> list[dict[str, Any]]:
    """One call to the OS provider; the returned rows are Windows' own statements about each anchor."""
    # The store list travels in the environment: with `-Command`, PowerShell appends trailing argv to
    # the command line and tries to execute them, so `Root` arrived as a cmdlet name.
    env = {"TA_STORES": ",".join(stores), "TA_LOCATION": location}
    if with_der:
        env["TA_WITH_DER"] = "1"
    full = {**os.environ, **env}
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user-controlled string
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PS],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=180,
            check=False,
            env=full,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(
            f"could not run the OS certificate provider: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return []
    if done.returncode != 0:
        print(
            f"provider failed ({done.returncode}): {done.stderr.strip()[:400]}",
            file=sys.stderr,
        )
        return []
    text = (done.stdout or "").strip()
    if not text:
        return []
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"provider output was not JSON: {exc}", file=sys.stderr)
        return []
    return [row for row in rows if isinstance(row, dict)]


SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

# A stated digest is a file name only after it passes this: the provider's string reaches the filesystem, so
# anything but 64 lower-case hex characters is refused before a path is built from it.
DIGEST = re.compile(r"[0-9a-f]{64}")


def _decode_der(value: object) -> bytes | None:
    """The provider's base64, or None when there is none or it does not decode strictly."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def retain_der(rows: list[dict[str, Any]], raw_dir: Path) -> dict[str, Any]:
    """Write each distinct certificate's DER to `raw_dir/<sha256>.der`, verified against its stated digest.

    Returns what was retained and what was refused. A row is refused when its DER is absent or not base64,
    when its stated digest is not a SHA-256, or when the SHA-256 of its bytes is not the stated digest; a
    refused row is never written. Existing files with the right bytes are left alone, and hash-named files
    this run did not verify are removed, so the directory is exactly this run's certificates.
    """
    verified: dict[str, bytes] = {}
    refused: list[dict[str, str]] = []
    for row in rows:
        stated = str(row.get("sha256") or "").lower()
        der = _decode_der(row.get("der_base64"))
        store = str(row.get("store") or "?")
        if der is None:
            refused.append({"store": store, "sha256": stated, "why": "no decodable DER"})
            continue
        if not DIGEST.fullmatch(stated):
            refused.append(
                {"store": store, "sha256": stated, "why": "stated digest is not a SHA-256"}
            )
            continue
        actual = hashlib.sha256(der).hexdigest()
        if actual != stated:
            refused.append(
                {
                    "store": store,
                    "sha256": stated,
                    "why": f"bytes hash to {actual}, not the stated digest",
                }
            )
            continue
        verified[stated] = der

    raw_dir.mkdir(parents=True, exist_ok=True)
    written = unchanged = 0
    for digest, der in sorted(verified.items()):
        # The check the file name promises, made again on the exact bytes about to be written.
        if hashlib.sha256(der).hexdigest() != digest:
            raise AssertionError(f"{digest}: verified bytes changed before writing")
        path = raw_dir / f"{digest}.der"
        if path.is_file() and path.read_bytes() == der:
            unchanged += 1
            continue
        tmp = path.with_suffix(".der.tmp")
        tmp.write_bytes(der)
        os.replace(tmp, path)
        written += 1
    pruned = 0
    for path in raw_dir.iterdir():
        stem = path.name.removesuffix(".der")
        if (
            path.is_file()
            and path.suffix == ".der"
            and DIGEST.fullmatch(stem)
            and stem not in verified
        ):
            path.unlink()
            pruned += 1
    return {
        "files": len(verified),
        "written": written,
        "unchanged": unchanged,
        "pruned": pruned,
        "refused": refused,
    }


def on_windows() -> bool:
    """The placement check, named so a test can answer it without rebinding `os.name` for the process."""
    return os.name == "nt"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument("--store", action="append", choices=COLLECTABLE_STORES, help="repeatable")
    parser.add_argument(
        "--location",
        choices=("LocalMachine", "CurrentUser"),
        default="LocalMachine",
        help="which hive to read. CurrentUser\\Root is where a user-installed root lands, and that "
        "is the one an incident needs to know about: it applies to this user's browsers and "
        "nothing else on the machine, and the machine-level artifact cannot see it.",
    )
    parser.add_argument(
        "--with-der",
        action="store_true",
        help="also retain each certificate's DER, verified against its SHA-256, at "
        "<data>/raw/<artifact stem>/<sha256>.der",
    )
    parser.add_argument("--grep", default=None, help="report anchors whose subject contains this")
    args = parser.parse_args()
    if not on_windows():
        print(
            f"this collector reads the Windows certificate store and cannot run on {sys.platform}.\n"
            "That is placement, not a missing dependency: the realized store of one machine only "
            "exists on that machine, so this is a host-resident probe. The container and Fargate "
            "collect program-published lists instead (certdata.txt, PEM bundles). On Linux the "
            "equivalent artifact is the ca-certificates bundle plus its hash, which "
            "collect_bundle.py already produces; on macOS it is `security "
            "trust-settings-export`. Neither is written yet.",
            file=sys.stderr,
        )
        return 3
    stores = args.store or list(DEFAULT_STORES)
    # The hive belongs in the artifact's name and program: a user-installed root and a machine-installed
    # one are different claims about different blast radii, and writing them to the same file would
    # quietly replace one with the other.
    hive = "machine" if args.location == "LocalMachine" else "user"

    rows = read_store(stores, args.with_der, args.location)
    if not rows:
        print("the provider returned no anchors; nothing is claimed")
        return 1

    per_store: dict[str, int] = dict.fromkeys(stores, 0)
    by_hash: dict[str, list[str]] = {}
    server_auth = 0
    eku_absent = 0
    anchors: list[dict[str, Any]] = []
    for row in rows:
        store = str(row.get("store") or "?")
        per_store[store] = per_store.get(store, 0) + 1
        digest = str(row.get("sha256") or "").lower()
        by_hash.setdefault(digest, []).append(store)
        flat = [str(v) for v in (row.get("eku") or [])]
        oids = [v for v in flat if v.count(".") >= 3]
        if not oids:
            eku_absent += 1
        if SERVER_AUTH in oids:
            server_auth += 1
        entry = {
            "store": store,
            "subject": row.get("subject"),
            "friendly_name": row.get("friendly") or None,
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "sha256": digest,
            "sha1": str(row.get("sha1") or "").lower(),
            "self_signed_reported": bool(row.get("self_signed")),
            "eku": oids,
            "eku_names": [v for v in flat if v.count(".") < 4],
        }
        der = _decode_der(row.get("der_base64"))
        if der is not None:
            entry["der_octets"] = len(der)
        anchors.append(entry)

    out_dir = Path(args.data) / "store"
    # Non-default store selections get their own file. `--location CurrentUser --store CA` landing on
    # `windows.user.json` would have silently replaced the user ROOT artifact collected an hour earlier,
    # and two artifacts with the same name are read as one store by anything downstream.
    slug = (
        "" if stores == list(DEFAULT_STORES) else "-" + "-".join(store.lower() for store in stores)
    )
    stem = f"windows.{hive}{slug}"
    dest = out_dir / f"{stem}.json"

    retained: dict[str, Any] | None = None
    if args.with_der:
        # Named by the artifact stem, as the other collectors' payloads are named under raw/, so the
        # directory and the artifact that describes it cannot be paired wrongly.
        retained = retain_der(rows, Path(args.data) / "raw" / stem)

    shared = {h: s for h, s in by_hash.items() if len(set(s)) > 1}
    doc: dict[str, Any] = {
        "artifact": "trustatlas.store.collect",
        "version": 1,
        "program": (
            f"Windows/schannel {hive} store"
            if stores == list(DEFAULT_STORES)
            else f"Windows/schannel {hive} store: {'+'.join(stores)}"
        ),
        "retrieved_at": _now(),
        "provenance": {
            "method": f"powershell.exe -NoProfile Cert:\\{args.location}\\<store>",
            "location": args.location,
            "host": platform.system().lower() + "/" + platform.release(),
            "stores": stores,
            "certificates_written": bool(args.with_der),
            "note": (
                "subject, validity and EKU are what Windows reports about each anchor; this tool "
                "decodes no certificate. Absent EKU is recorded as absent, and what absence means "
                "is RFC 5280's to say, not this artifact's. The join key here is the certificate "
                "SHA-256; the SPKI SHA-256 that would join a cross-signed copy of one key is "
                "asn1core's to produce."
            ),
        },
        "counts": {
            "anchors": len(anchors),
            "distinct_certificates": len(by_hash),
            "per_store": per_store,
            "in_more_than_one_store": len(shared),
            "with_server_auth_eku": server_auth,
            "with_no_eku_extension": eku_absent,
        },
        "anchors": sorted(anchors, key=lambda a: (a["store"], a["subject"] or "")),
    }
    if retained is not None:
        doc["provenance"]["raw"] = {
            "dir": f"raw/{stem}",
            "files": retained["files"],
            "refused": len(retained["refused"]),
        }

    out_dir.mkdir(parents=True, exist_ok=True)
    dest.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))

    print(f"{len(anchors)} anchors, {len(by_hash)} distinct certificates -> {dest}")
    if retained is not None:
        print(
            f"  raw/{stem}: {retained['files']} DER files verified against their names "
            f"({retained['written']} written, {retained['unchanged']} unchanged, "
            f"{retained['pruned']} stale removed)"
        )
        for refusal in retained["refused"]:
            print(
                f"  refused {refusal['store']} {refusal['sha256'] or '<no digest>'}: {refusal['why']}",
                file=sys.stderr,
            )
    for store, count in sorted(per_store.items()):
        print(f"  {store:<11} {count}")
    print(
        f"  {len(shared)} certificates appear in more than one store; {server_auth} carry server-auth "
        f"EKU; {eku_absent} report no EKU extension at all"
    )
    if args.grep:
        hits = [a for a in anchors if args.grep.lower() in (a["subject"] or "").lower()]
        print(f"  subject contains {args.grep!r}: {len(hits)}")
        for hit in hits:
            print(f"    {hit['store']:<11} {hit['subject']}")
    if retained is not None and retained["refused"]:
        # The artifact is written, but a raw directory short of its certificates must not exit green.
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
