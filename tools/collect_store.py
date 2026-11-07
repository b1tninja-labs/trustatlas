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
host you are auditing and not publishing from.

Usage:
    python tools/collect_store.py --data M:\\trustatlas
    python tools/collect_store.py --store Root --store Disallowed --with-der
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import platform
import subprocess  # noqa: S404 - the OS certificate store is only reachable through the OS provider
import sys
from pathlib import Path
from typing import Any

DEFAULT_STORES = ("Root", "AuthRoot", "Disallowed")

# Ask Windows PowerShell's certificate provider for each anchor and emit one JSON object. The fields
# are what Windows computes and reports; nothing here is derived from the DER bytes themselves.
PS = r"""
$ErrorActionPreference = 'Stop'
$out = @()
foreach ($store in ($env:TA_STORES -split ',')) {
  $path = "Cert:\LocalMachine\$store"
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


def read_store(stores: list[str], with_der: bool) -> list[dict[str, Any]]:
    """One call to the OS provider; the returned rows are Windows' own statements about each anchor."""
    # The store list travels in the environment: with `-Command`, PowerShell appends trailing argv to
    # the command line and tries to execute them, so `Root` arrived as a cmdlet name.
    env = {"TA_STORES": ",".join(stores)}
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--data", default=os.environ.get("TRUSTATLAS_DATA", "M:\\trustatlas")
    )
    parser.add_argument(
        "--store", action="append", choices=DEFAULT_STORES, help="repeatable"
    )
    parser.add_argument(
        "--with-der", action="store_true", help="write the certificates too"
    )
    parser.add_argument(
        "--grep", default=None, help="report anchors whose subject contains this"
    )
    args = parser.parse_args()
    stores = args.store or list(DEFAULT_STORES)

    rows = read_store(stores, args.with_der)
    if not rows:
        print("the provider returned no anchors; nothing is claimed")
        return 1

    per_store: dict[str, int] = {store: 0 for store in stores}
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
        der = row.get("der_base64")
        if der:
            entry["der_octets"] = len(base64.b64decode(der))
        anchors.append(entry)

    shared = {h: s for h, s in by_hash.items() if len(set(s)) > 1}
    doc = {
        "artifact": "trustatlas.store.collect",
        "version": 1,
        "program": "Windows/schannel machine store",
        "retrieved_at": _now(),
        "provenance": {
            "method": "powershell.exe -NoProfile Cert:\\LocalMachine\\<store>",
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

    if args.with_der:
        der_dir = Path(args.data) / "store" / "der"
        der_dir.mkdir(parents=True, exist_ok=True)
        for row in rows:
            der = row.get("der_base64")
            digest = str(row.get("sha256") or "").lower()
            if der and digest:
                (der_dir / f"{digest}.der").write_bytes(base64.b64decode(der))

    out_dir = Path(args.data) / "store"
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "windows.machine.json"
    dest.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))

    print(f"{len(anchors)} anchors, {len(by_hash)} distinct certificates -> {dest}")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
