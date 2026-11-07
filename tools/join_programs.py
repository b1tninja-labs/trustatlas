"""Join two trust-set artifacts on certificate SHA-256 and report what each side cannot see.

The map's thesis is that trust sets are per-program and dated, so the interesting number is the
overlap and, more than the overlap, the two one-sided remainders. Both artifacts carry
`retrieved_at`, so the join can state that it is comparing a store read on one day with a bundle
read on another — which is a fact about the answer, not a footnote.

Limits stated by the tool itself. The join key is the certificate's SHA-256 of DER, so two
certificates sharing one key (a root and its cross-signed twin) are two entries here, and the
overlap understates agreement between programs that disagree only about which certificate of a key
they ship. Closing that needs SPKI SHA-256, which is `asn1core`'s. And a bundle artifact carries
hashes only, so the bundle's side of a difference can be counted but not named.

Usage:
    python tools/join_programs.py --a windows.machine.json --b certifi.json --data M:\\trustatlas
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


def load(data: str, name: str) -> dict[str, Any]:
    path = Path(name)
    if not path.is_absolute():
        path = Path(data) / "store" / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"cannot read artifact {path}: {type(exc).__name__}: {exc}", file=sys.stderr
        )
        raise SystemExit(1)


def index(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = doc.get("anchors") or doc.get("certificates") or []
    return {str(r.get("sha256", "")).lower(): r for r in rows if r.get("sha256")}


def is_delegator(row: dict[str, Any], bit: str) -> bool:
    """Whether the program lets this anchor issue under one trust bit.

    NSS states bits per object (`SERVER_AUTH: TRUSTED_DELEGATOR`), which is why the same file can carry
    an S/MIME-only root and a TLS root and count both. Bundles and keystores state no bits at all, so
    an artifact that says nothing is never filtered by this -- absence of a claim is not a claim of
    exclusion, and treating it as one would silently delete half a trust set.
    """
    trust = row.get("trust") or {}
    value = trust.get(bit)
    return isinstance(value, str) and value.endswith("_DELEGATOR")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", default=os.environ.get("TRUSTATLAS_DATA", "/data"))
    parser.add_argument(
        "--a", required=True, help="first artifact (a store or bundle JSON)"
    )
    parser.add_argument("--b", required=True, help="second artifact")
    parser.add_argument(
        "--only", default="both", choices=("both", "a", "b"), help="list remainders"
    )
    parser.add_argument(
        "--a-trust",
        default=None,
        help="restrict A to anchors the program trusts as delegators under this bit, e.g. SERVER_AUTH",
    )
    parser.add_argument(
        "--b-trust",
        default=None,
        help="restrict B the same way. Comparing a TLS store with an all-bits program list without "
        "this overstates the disagreement.",
    )
    parser.add_argument("--out", default=None, help="write the join artifact here")
    args = parser.parse_args()

    doc_a, doc_b = load(args.data, args.a), load(args.data, args.b)
    a, b = index(doc_a), index(doc_b)
    totals = {"a": len(a), "b": len(b)}
    for bit, side in ((args.a_trust, "a"), (args.b_trust, "b")):
        if not bit:
            continue
        kept = {
            k: v for k, v in (a if side == "a" else b).items() if is_delegator(v, bit)
        }
        (a if side == "a" else b).clear()
        (a if side == "a" else b).update(kept)
        print(
            f"  {side} filtered to {len(kept)} anchors trusted as {bit} delegators "
            f"(of {totals[side]}); the rest are trusted for other purposes or state nothing"
        )
    shared = sorted(set(a) & set(b))
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    named = "subject" in next(iter(a.values()), {})

    print(
        f"{doc_a.get('program', args.a)} ({doc_a.get('retrieved_at', '?')}) x "
        f"{doc_b.get('program', args.b)} ({doc_b.get('retrieved_at', '?')})"
    )
    print(
        f"  {len(a)} vs {len(b)} certificates; shared {len(shared)}; only-a {len(only_a)}; only-b {len(only_b)}"
    )
    # The derivation check is the reason the join exists: "certifi derives from NSS built-ins" is a
    # claim about documentation until one side's hashes come entirely from the other's.
    if only_a and only_b:
        verdict = "neither is a subset of the other"
    elif only_a:
        verdict = f"{doc_b.get('program')} is a subset of {doc_a.get('program')}"
    elif only_b:
        verdict = f"{doc_a.get('program')} is a subset of {doc_b.get('program')}"
    else:
        verdict = "identical certificate sets"
    print(f"  derivation check: {verdict}")
    if named and args.only in ("both", "a"):
        for digest in only_a:
            print(
                f"  only in {doc_a.get('program')}: {a[digest].get('subject')} [{a[digest]['store']}]"
            )
    if not named or args.only == "b":
        for digest in only_b[:20]:
            row = b[digest]
            # A bundle names nothing, but a keystore carries an alias and a store carries labels, and
            # neither is a subject. Falling back to the digest prefix here would hide the one name this
            # side has, so every non-subject name the artifacts do carry is tried, in that order.
            name = (
                row.get("subject")
                or row.get("alias")
                or row.get("labels")
                or digest[:16] + "..."
            )
            print(f"  only in {doc_b.get('program')}: {name}")
        if len(only_b) > 20:
            print(
                f"  ... {len(only_b) - 20} more, all hash-only: a bundle artifact names nothing"
            )

    if args.out:
        doc = {
            "artifact": "trustatlas.join",
            "version": 1,
            "retrieved_at": doc_a.get("retrieved_at"),
            "provenance": {
                "a": args.a,
                "b": args.b,
                "key": "certificate SHA-256 of DER",
                "trust_filter": {
                    side: bit
                    for side, bit in (("a", args.a_trust), ("b", args.b_trust))
                    if bit
                },
                "totals_before_filter": totals,
                "limit": (
                    "two certificates holding one key are two entries, so the overlap understates "
                    "programs that differ only in which certificate of a key they ship; SPKI "
                    "SHA-256 (asn1core) is what would collapse them"
                ),
            },
            "counts": {"a": len(a), "b": len(b), "shared": len(shared)},
            "shared": shared,
            "only_a": only_a,
            "only_b": only_b,
        }
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes((json.dumps(doc, indent=1) + "\n").encode("utf-8"))
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    main()
