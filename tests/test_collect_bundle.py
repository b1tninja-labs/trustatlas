"""Pin what `tools/collect_bundle.py` may claim about a PEM bundle — and what it must never claim.

Every case here is a defect this repository already recorded, or an invariant whose loss would turn a
number into a lie. The digests are computed from the fixture bytes inside the tests rather than copied
from a run: a pinned literal would only prove that nothing changed, while deriving them proves the
split-and-decode round-trip and lets the same check read the *artifact* back off disk (see
`test_the_written_artifact_carries_these_digests_and_counts`).

The measurements behind these fixtures are written down in `ROADMAP.md`, and they are what makes the
text-handling cases worth having: node's compiled-in set arrived with 144 of 145 anchors "named" by a
PEM delimiter, Android's AOSP bundle labelled 148 of 149 names with the *previous* certificate's subject,
and the first run of `collect_java.py` labelled all 109 entries with a date. In all three the digests
stayed right — which is exactly how each one hid.

Offline by design: nothing here opens a socket, needs `M:\trustatlas`, or asks for a JDK, a node binary
or 350 KB of Google's archive. The shapes are reproduced as text and as a tar built in the test.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import collect_bundle  # the script under test; `pythonpath = ["tools"]` also puts it in reach

BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"


def synthetic_der(marker: bytes) -> bytes:
    """A DER SEQUENCE whose payload carries `marker`, so distinct anchors hash distinctly.

    This is a *byte string* and not a certificate — nothing here decodes it, which is the rule `AGENTS.md`
    sets for this directory. Only its SHA-256 matters to the code under test. The padding holds every
    fixture to one length, so a count can never be confounded with a size, and two blocks differing only
    in their marker cannot collide.
    """
    body = bytes([0x30, 0x03, 0x02, 0x01, 0x01]) + marker + b"\x00" * (64 - len(marker))
    return bytes([0x30, len(body)]) + body


def pem_for(marker: bytes) -> str:
    """One PEM block holding the DER for `marker`, wrapped at 64 characters like every real bundle."""
    b64 = base64.b64encode(synthetic_der(marker)).decode("ascii")
    return "\n".join([BEGIN, *(b64[i : i + 64] for i in range(0, len(b64), 64)), END])


def digest_of(marker: bytes) -> str:
    return hashlib.sha256(synthetic_der(marker)).hexdigest()


def bundle(*headers: str) -> str:
    """A bundle whose blocks are marked `A`, `B`, `C`, ... with `headers[n]` above block n.

    Block n+1 is always a *different* certificate, so a test that wants a duplicate repeats a marker
    through `blocks()` instead of relying on two headers happening to describe one anchor.
    """
    return blocks(*[(bytes([0x41 + index]), header) for index, header in enumerate(headers)])


def blocks(*items: tuple[bytes, str]) -> str:
    """A bundle of the given (marker, header) pairs, in order; an empty header means no comment."""
    parts: list[str] = []
    for marker, header in items:
        if header:
            parts.append(header.rstrip("\n"))
        parts.append(pem_for(marker))
    return "\n".join(parts) + "\n"


def entry(seen: dict[str, dict[str, object]], marker: bytes) -> dict[str, Any]:
    """The row for a block the bundle marked, looked up by the digest it must have produced."""
    digest = digest_of(marker)
    assert digest in seen, f"{marker!r} hashed to something else: {sorted(seen)}"
    return seen[digest]


def tar_payload(members: dict[str, str]) -> bytes:
    """A gzipped tar holding `members` as files — the shape Gitiles serves Android's bundle in.

    Members are written in the given order and read back in it, so a test that relies on one file
    following another (the off-by-one below) does not depend on how an archive happens to sort.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in members.items():
            raw = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(raw))
    with tarfile.open(fileobj=io.BytesIO(buf.getvalue()), mode="r:*") as tar:
        assert [m.name for m in tar.getmembers()] == list(members), "archive reordered its members"
    return buf.getvalue()


def aosp_member(marker: bytes, subject: str) -> str:
    """One `<subject hash>.0` file: the PEM, then the OpenSSL text dump AOSP appends after it."""
    return (
        f"{pem_for(marker)}\n"
        "Certificate:\n"
        "    Data:\n"
        "        Version: 3 (0x2)\n"
        f"        Subject: {subject}\n"
        "        Subject Public Key Info:\n"
        "            Public Key Algorithm: rsaEncryption\n"
    )


def run_main(*argv: str) -> int:
    """Call the CLI with argv set, so a usage error surfaces as a failure instead of exiting the suite."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", ["collect_bundle.py", *argv])
        return collect_bundle.main()


# --- digests and counts ---------------------------------------------------------------------------


def test_each_block_hashes_to_its_own_der_and_the_counts_add_up() -> None:
    text = bundle("# Subject: CN=Alpha Test Root\n", "# Subject: CN=Beta Test Root\n")
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts == {
        "pem_blocks": 2,
        "distinct_certificates": 2,
        "duplicate_blocks": 0,
        "malformed_blocks": 0,
        "fingerprint_checked": 0,
        "fingerprint_agrees": 0,
        "named": 2,
        "subject_named": 2,
        "header_dumps_discarded": 0,
        "legacy_label_blocks": 0,
    }
    assert counts["distinct_certificates"] == len(seen)
    for marker in (b"A", b"B"):
        row = entry(seen, marker)
        # The digest is SHA-256 of the *DER*, not of the base64 text or of the PEM block: a join across
        # programs compares these values, so a digest of anything else would report two programs that
        # ship the same anchor as disagreeing.
        assert row["sha256"] == digest_of(marker)
        assert row["der_octets"] == len(synthetic_der(marker))
        assert row["store"] == "fixture"


def test_the_digest_ignores_how_the_base64_is_wrapped() -> None:
    """Same bytes, different line width, same identity.

    `join_programs.py` joins on this digest across bundles assembled by different maintainers, so the
    value must be a property of the DER and never of the text layout around it.
    """
    der = synthetic_der(b"A")
    wide = base64.b64encode(der).decode("ascii")
    narrow = "\n".join(wide[i : i + 20] for i in range(0, len(wide), 20))
    text = f"{BEGIN}\n{narrow}\n{END}\n"

    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["distinct_certificates"] == 1
    assert set(seen) == {hashlib.sha256(der).hexdigest()}


def test_a_repeated_certificate_counts_as_a_duplicate_and_not_a_second_anchor() -> None:
    """Blocks and anchors are different numbers, and the join needs both to be right.

    A bundle that ships one certificate twice must produce one row — otherwise a program's trust set is
    inflated by its own formatting — while the block count still reports every BEGIN marker it saw.
    """
    text = blocks(
        (b"A", "# Subject: CN=Alpha Test Root"),
        (b"A", ""),
        (b"B", "# Subject: CN=Alpha Again Root"),
    )
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["pem_blocks"] == 3
    assert counts["duplicate_blocks"] == 1
    assert counts["distinct_certificates"] == len(seen) == 2
    assert set(seen) == {digest_of(b"A"), digest_of(b"B")}


def test_a_block_that_is_not_base64_is_counted_and_the_rest_survives() -> None:
    """A malformed block is a counted refusal, never a crash and never a silent drop.

    `verify_provenance.py`'s re-derivation check reports this count as the reason a marker total and an
    anchor total differ; if a bad block vanished uncounted, that arithmetic would hide a broken split.
    """
    text = "\n".join(
        ["# Subject: CN=Broken Test Root", f"{BEGIN}", "!!!! not base64 !!!!", END, ""]
    ) + bundle("# Subject: CN=Alpha Test Root\n")
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["pem_blocks"] == 2
    assert counts["malformed_blocks"] == 1
    assert counts["distinct_certificates"] == 1
    assert set(seen) == {digest_of(b"A")}


def test_the_counts_account_for_every_block_that_was_seen() -> None:
    """The identity `verify_provenance.py` relies on when it reports a non-lossless extraction.

    Every BEGIN marker is exactly one of a distinct digest, a duplicate of one, or a malformed block. If
    the three ever stop summing to the marker count, the number of anchors has become a property of this
    file's split rather than of the bundle — and the artifact would say so without meaning it.
    """
    text = blocks(
        (b"A", "# Subject: CN=Alpha Test Root"),
        (b"B", ""),
        (b"C", "# Subject: CN=Beta Test Root"),
        (b"D", "# Subject: CN=Gamma Test Root"),
    )
    # Replace block C's whole PEM, not its base64 string: `pem_for` wraps at 64 columns, so the unwrapped
    # base64 never occurs in the text and a replace on it would silently leave C well-formed.
    assert pem_for(b"C") in text
    text = text.replace(pem_for(b"C"), f"{BEGIN}\n%%%%\n{END}")

    _seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert (
        counts["distinct_certificates"] + counts["duplicate_blocks"] + counts["malformed_blocks"]
        == counts["pem_blocks"]
    )
    assert counts["pem_blocks"] == 4
    assert counts["malformed_blocks"] == 1


# --- `-----` is never a name ----------------------------------------------------------------------


def test_a_bundle_with_no_comments_names_nothing_rather_than_naming_a_delimiter() -> None:
    """The node regression: 144 of 145 compiled-in anchors arrived "named" by `-----END CERTIFICATE-----`.

    A block with nothing above it must carry no name. Before the header was cut at the previous block's
    END marker, the walk backwards ran into that trailing delimiter line and reported it as a subject —
    so a store read through a reader looked *populated* while every one of its names was PEM syntax.
    """
    text = "\n".join([pem_for(b"A"), pem_for(b"B"), pem_for(b"C")]) + "\n"
    seen, counts = collect_bundle.index_pem(text, program="node.bundled")

    assert counts["distinct_certificates"] == 3
    # The measurement this pins: three blocks, none named. Read the other way it says "0 of 145", and a
    # reader can tell an unnamed store from a wrongly named one; it cannot tell those apart from 145.
    assert counts["named"] == 0
    assert counts["subject_named"] == 0
    for row in seen.values():
        assert row["subject"] is None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (END, None),
        (BEGIN, None),
        (f"# {END}", None),
        (f"{BEGIN} ", None),
        ("# Subject: CN=Alpha Test Root", "CN=Alpha Test Root"),
    ],
    ids=["end", "begin", "commented-end", "begin-with-space", "real-subject"],
)
def test_a_pem_delimiter_line_is_never_recorded_as_a_name(line: str, expected: str | None) -> None:
    """Whatever a delimiter looks like, alone above a block, it stays out of the name field.

    The last case is the control: the rule that rejects a delimiter must not also reject the one line in
    a bundle that genuinely names the certificate, or the fix would arrive as an unnamed store instead.
    """
    seen, counts = collect_bundle.index_pem(bundle(f"{line}\n"), program="fixture")

    assert entry(seen, b"A")["subject"] == expected
    assert counts["named"] == (1 if expected else 0)


def test_a_dump_that_survives_the_extractor_still_cannot_be_read_as_a_name() -> None:
    """The defect itself, rather than one of the two fixes for it.

    `pem_from_tar` normally drops the trailing text, but `index_pem` is imported by `collect_java.py` and
    `verify_provenance.py`, so the cut at the previous block's END marker has to hold on its own for
    whatever those callers hand it. Here certificate A's dump sits directly above certificate B.

    A dump is never read as a name, for either block (row `ta.readers_remaining`): the header region that
    holds it is discarded whole and counted, so B gets no name and A gets none from text below it.
    """
    dumped = f"{END}\nCertificate:\n    Data:\n        Subject: CN=Alpha Android Root\n"
    text = "\n".join([pem_for(b"A"), dumped, pem_for(b"B"), ""])

    seen, counts = collect_bundle.index_pem(text, program="android.aosp")

    assert counts["distinct_certificates"] == 2
    assert counts["header_dumps_discarded"] == 1
    assert counts["named"] == counts["subject_named"] == 0
    # The Android measurement — 148 of 149 wrong — told from the fixture's side: the dump's subject lands
    # on no block at all.
    assert entry(seen, b"B")["subject"] is None
    assert entry(seen, b"A")["subject"] is None
    assert "CN=Alpha Android Root" not in json.dumps(list(seen.values()))


def test_a_dump_that_is_not_the_whole_header_still_discards_the_whole_header() -> None:
    """A keyed line sharing a region with a dump is not trusted either: the region is dropped, not mined.

    Keeping the lines "around" a dump would need to know where the dump ends, which is OpenSSL's text
    format and not this file's business.
    """
    text = bundle(
        "# Subject: CN=Looks Fine Root\nCertificate:\n    Data:\n        Subject: CN=Other Root\n"
    )
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["header_dumps_discarded"] == 1
    assert entry(seen, b"A")["subject"] is None
    assert entry(seen, b"A")["alias"] is None


# --- Android: the mislabel off-by-one -------------------------------------------------------------


def test_the_archive_keeps_only_pem_spans_so_no_subject_lands_on_the_next_anchor() -> None:
    """Android's off-by-one: the backward walk read `Subject:` out of the *previous* file's dump.

    Measured 148 of 149 names wrong while every digest stayed correct. Each fixture member below carries
    its own subject in its own dump, so an off-by-one would be directly visible as a name that belongs to
    the neighbour. The dumps are dropped by design, so no anchor gets a subject at all: each is named by
    its member filename, recorded as an `alias` because `252252d2.0` is a subject hash and not a DN.
    """
    paths = {
        b"A": "system/etc/security/cacerts/0a775be3.0",
        b"B": "system/etc/security/cacerts/252252d2.0",
        b"C": "system/etc/security/cacerts/7231fd9f.0",
    }
    subjects = {
        b"A": "CN=Alpha Android Root",
        b"B": "CN=Beta Android Root",
        b"C": "CN=Gamma Android Root",
    }
    payload = tar_payload({paths[m]: aosp_member(m, subjects[m]) for m in paths})

    text, members, dumped = collect_bundle.pem_from_tar(payload)
    seen, counts = collect_bundle.index_pem(text, program="android.aosp", name_key="alias")

    assert (members, dumped) == (3, 3)
    assert counts["pem_blocks"] == counts["distinct_certificates"] == 3
    assert counts["header_dumps_discarded"] == 0
    assert counts["named"] == 3
    assert counts["subject_named"] == 0
    for marker, path in paths.items():
        row = entry(seen, marker)
        assert row["alias"] == path
        assert row["subject"] is None
    # No subject from any dump, this anchor's or a neighbour's, reaches any row.
    assert not any(name in json.dumps(list(seen.values())) for name in subjects.values())
    # Nothing but PEM spans survives the extractor, so no dump text can reach a later reader of this text.
    assert "Subject:" not in text.replace("Alias name: ", "")
    assert text.count(BEGIN) == text.count(END) == 3


def test_the_dropped_dumps_are_counted_because_a_quiet_drop_is_its_own_lie() -> None:
    """The fix is only honest while the artifact says what it threw away.

    `dumped` is what lets a reader tell "Android ships one anchor per file plus a text dump" from
    "Android ships 149 certificates and no comments". A future edit that stops counting would make the
    provenance claim unverifiable, so the count is pinned here on a mixed archive.
    """
    payload = tar_payload(
        {
            "a/0a775be3.0": aosp_member(b"A", "CN=Alpha Android Root"),
            "b/252252d2.0": pem_for(b"B") + "\n",  # PEM only: counted, not dumped
            "c/7231fd9f.0": aosp_member(b"C", "CN=Gamma Android Root"),
        }
    )

    _text, members, dumped = collect_bundle.pem_from_tar(payload)

    assert members == 3
    assert dumped == 2


def test_the_android_fix_does_not_move_a_single_digest() -> None:
    """The property that hid the defect for a whole release: digests never look at the text.

    Asserting it the other way now means a future change to the extractor that *does* disturb hashing —
    a span boundary off by a byte, say — fails here instead of quietly changing a store's membership.
    """
    payload = tar_payload(
        {
            "a/0a775be3.0": aosp_member(b"A", "CN=Alpha Android Root"),
            "b/252252d2.0": aosp_member(b"B", "CN=Beta Android Root"),
        }
    )
    text, _members, _dumped = collect_bundle.pem_from_tar(payload)
    seen, counts = collect_bundle.index_pem(text, program="android.aosp")

    assert set(seen) == {digest_of(b"A"), digest_of(b"B")}
    assert counts["malformed_blocks"] == 0
    assert all(
        row["der_octets"] == len(synthetic_der(m))
        for m, row in ((b"A", seen[digest_of(b"A")]), (b"B", seen[digest_of(b"B")]))
    )


# --- subject vs alias precedence ------------------------------------------------------------------


def keytool_member(
    alias: str, marker: bytes, owner: str | None = "CN=Java Test Root, O=Test"
) -> str:
    """`keytool -list -rfc`: an alias above the block, and JDK 26's boilerplate in between.

    `owner=None` leaves out the `Owner:` line, for a reader that prints only the alias.
    """
    owner_line = f"Owner: {owner}\n" if owner is not None else ""
    return (
        f"Alias name: {alias}\n"
        "Creation date: Nov 7, 2026\n"
        "Entry type: trustedCertEntry\n"
        f"{owner_line}"
        "\n"
        f"{pem_for(marker)}\n"
    )


def test_a_keystore_alias_is_recorded_as_an_alias_and_leaves_subject_absent() -> None:
    """An alias is a nickname the keystore chose; writing it into `subject` would overstate the claim.

    `--reader-name-key alias` (what `collect_java.py` passes) therefore fills `alias`, keeps `subject`
    null, and the two counts separate: 1 anchor named, 0 subjects named. The fixture carries no `Owner:`
    line, because an Owner *is* a subject (see the test after next) and would rightly fill the field.
    """
    text = keytool_member("javatestroot", b"A", owner=None)
    seen, counts = collect_bundle.index_pem(text, program="java.cacerts", name_key="alias")

    row = entry(seen, b"A")
    assert row["alias"] == "javatestroot"
    assert row["subject"] is None
    assert row["store"] == "java.cacerts"
    assert counts["named"] == 1
    assert counts["subject_named"] == 0


def test_a_bundle_subject_is_recorded_as_a_subject_with_no_alias_invented() -> None:
    """The other side of the same rule: with `name_key="subject"` the alias field is present and null.

    certifi carries a maintainer's `# Subject:` comment, which is a string in the file and so fair to
    record; an alias would be a claim about a keystore that does not exist here. Both keys are always
    present, so a reader of the artifact never has to tell "absent" from "not looked for".
    """
    text = bundle("# Subject: CN=Curl Test Root\n")
    seen, counts = collect_bundle.index_pem(text, program="curl")

    row = entry(seen, b"A")
    assert row["subject"] == "CN=Curl Test Root"
    assert row["alias"] is None
    assert counts["named"] == counts["subject_named"] == 1


def test_owner_and_alias_are_kept_apart_even_when_both_are_present() -> None:
    """`Owner:` is Java's word for the subject; `Alias name:` is its word for a nickname.

    keytool prints both, so a reader that treats them alike either loses the distinguished name or
    invents one. With the alias as the name key, Owner still lands in `subject` and the nickname stays in
    `alias`, which is what lets a join name this side by DN *and* by nickname.
    """
    text = keytool_member("javatestroot", b"A")
    seen, _counts = collect_bundle.index_pem(text, program="java.cacerts", name_key="alias")

    row = entry(seen, b"A")
    assert row["subject"] == "CN=Java Test Root, O=Test"
    assert row["alias"] == "javatestroot"


def test_a_subject_beats_an_alias_when_a_single_block_carries_both() -> None:
    """Precedence, stated: each line lands in its own field, and neither displaces the other.

    `join_programs.py` prefers `subject` over `alias` when it lists a remainder, so the subject must be the
    DN the file states, never the nickname; the alias is still a string the file states, so it is kept in
    its own field rather than discarded. The order of the two lines does not matter.
    """
    for header in (
        "Alias name: a-nickname\nSubject: CN=Preferred Test Root\n",
        "Subject: CN=Preferred Test Root\nAlias name: a-nickname\n",
    ):
        seen, counts = collect_bundle.index_pem(
            bundle(header), program="fixture", name_key="subject"
        )
        row = entry(seen, b"A")
        assert row["subject"] == "CN=Preferred Test Root", header
        assert row["alias"] == "a-nickname", header
        assert counts["named"] == counts["subject_named"] == 1


def test_a_keyed_subject_is_not_displaced_by_a_nearer_unkeyed_line() -> None:
    """certifi's shape: `# Subject:` sits above `# Label:` and the fingerprint lines.

    Walking backwards meets `Label: "..."` first. Before the fix the walk stopped at the first unkeyed line
    and recorded the label as the subject; the keyed `Subject:` line further up now wins.
    """
    text = bundle(
        "# Issuer: CN=Certifi Test Root\n"
        "# Subject: CN=Certifi Test Root\n"
        '# Label: "Certifi Test Root"\n'
        "# Serial: 1234567890\n"
    )
    seen, _counts = collect_bundle.index_pem(text, program="certifi")

    assert entry(seen, b"A")["subject"] == "CN=Certifi Test Root"


def test_an_unkeyed_line_goes_only_to_the_name_key() -> None:
    """With `name_key="alias"` a plain comment line is an alias candidate, and never also a subject."""
    seen, counts = collect_bundle.index_pem(
        bundle("# some-keystore-nickname\n"), program="fixture", name_key="alias"
    )

    row = entry(seen, b"A")
    assert row["alias"] == "some-keystore-nickname"
    assert row["subject"] is None
    assert (counts["named"], counts["subject_named"]) == (1, 0)


def test_an_unknown_name_key_is_refused() -> None:
    with pytest.raises(ValueError, match="name_key"):
        collect_bundle.index_pem(bundle(""), program="fixture", name_key="label")


def test_boilerplate_between_the_alias_and_the_block_does_not_become_the_name() -> None:
    """JDK 26's regression, which the alias fix nearly hid.

    `Creation date:` and `Entry type:` sit between the alias and the PEM block. The first run of
    `collect_java.py` took "Creation date: Nov 7, 2026" as the name of all 109 entries and stopped before
    it ever reached `Alias name:` — so these lines are skipped, not merely outranked.
    """
    text = bundle("Creation date: Nov 7, 2026\nEntry type: trustedCertEntry\n")
    seen, counts = collect_bundle.index_pem(text, program="java.cacerts", name_key="alias")

    row = entry(seen, b"A")
    assert row["alias"] is None
    assert "Nov 7, 2026" not in json.dumps(row)
    assert counts["named"] == 0


def test_a_bare_line_above_a_block_is_taken_as_the_name_of_that_block() -> None:
    """The fallback that makes the off-by-one dangerous, kept on purpose.

    Some bundles carry a plain comment with no `key:` prefix; recording it is what lets a difference be
    *named* instead of only counted. Pinning the fallback also pins the cut: the name found is this
    block's, never its predecessor's trailing text.
    """
    text = bundle("# A maintainer wrote this line\n")
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert entry(seen, b"A")["subject"] == "A maintainer wrote this line"
    assert counts["named"] == 1


@pytest.mark.parametrize(
    "line",
    ["Issuer: CN=Some Test CA", "Serial: 00:11:22", "Validity: forever", "Public Key: rsa", "abcd"],
    ids=["issuer", "serial", "validity", "public-key", "too-short"],
)
def test_a_field_that_is_not_a_name_is_never_used_as_one(line: str) -> None:
    """The skip list, one line at a time.

    Each of these describes something other than who the certificate is, and a five-character floor keeps
    stray punctuation and section markers out of the name field too: `abcd` has four characters, so the
    floor (`len < 5`) refuses it, where the earlier case `short` had five and was accepted.
    """
    seen, counts = collect_bundle.index_pem(bundle(f"# {line}\n"), program="fixture")

    assert entry(seen, b"A")["subject"] is None
    assert counts["named"] == 0


# --- stated fingerprints --------------------------------------------------------------------------


def fingerprint_lines(digest: str, *, colons: bool = False, upper: bool = False) -> str:
    shown = digest.upper() if upper else digest
    if colons:
        shown = ":".join(shown[i : i + 2] for i in range(0, len(shown), 2))
    return f"# SHA256 Fingerprint: {shown}\n"


def test_a_stated_sha256_is_compared_against_the_digest_computed_here() -> None:
    """Agreement is the proof that the split and decode were right for that certificate.

    A bundle's own `SHA256 Fingerprint:` line is an independent description of the same bytes, so when it
    matches what this file hashed, the PEM handling is verified by the data rather than by a fixture —
    which is how 120 curl certificates can check the collector all at once.
    """
    want = digest_of(b"A")
    text = bundle(f"# Subject: CN=Fingerprinted Test Root\n{fingerprint_lines(want)}")
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    row = entry(seen, b"A")
    assert row["bundle_fingerprint_agrees"] is True
    assert counts["fingerprint_checked"] == 1
    assert counts["fingerprint_agrees"] == 1


def test_a_stated_fingerprint_survives_colons_and_capitals() -> None:
    """Maintainers write the same digest four ways; only its value may matter.

    Colon-separated and upper-case are both common (keytool prints `SHA256:` with colons), and refusing
    to normalise them would report a checked bundle as an unchecked one.
    """
    want = digest_of(b"A")
    for header in (
        fingerprint_lines(want, colons=True),
        fingerprint_lines(want, upper=True),
        fingerprint_lines(want, colons=True, upper=True),
    ):
        seen, counts = collect_bundle.index_pem(bundle(header), program="fixture")
        assert entry(seen, b"A")["bundle_fingerprint_agrees"] is True, header
        assert (counts["fingerprint_checked"], counts["fingerprint_agrees"]) == (1, 1)


def test_a_stated_fingerprint_that_disagrees_is_recorded_as_disagreeing() -> None:
    """The whole value of the check is that it can say no.

    A collector that only counted matches would report `fingerprint_agrees == fingerprint_checked` for a
    bundle whose digests came out wrong, which is precisely the silent pass this field exists to prevent.
    """
    text = bundle(fingerprint_lines(digest_of(b"B")))
    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert entry(seen, b"A")["bundle_fingerprint_agrees"] is False
    assert counts["fingerprint_checked"] == 1
    assert counts["fingerprint_agrees"] == 0


def test_a_fingerprint_of_the_wrong_shape_is_not_counted_as_a_check() -> None:
    """An MD5 or SHA-1 line says nothing about SHA-256 of DER, so it must not enter the tally.

    Both counters are used in `main`'s summary ("the bundle states a SHA-256 for N certificates"), and a
    32-hex-digit MD5 admitted here would make that sentence false.
    """
    md5 = hashlib.md5(synthetic_der(b"A"), usedforsecurity=False).hexdigest()
    text = bundle(f"# Fingerprint: {md5}\n", f"# SHA1 Fingerprint: {'ab' * 20}\n")

    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert "bundle_fingerprint_agrees" not in entry(seen, b"A")
    assert counts["fingerprint_checked"] == 0
    assert counts["fingerprint_agrees"] == 0


# --- the artifact, end to end ---------------------------------------------------------------------


def test_the_written_artifact_carries_these_digests_and_counts(tmp_path: Path) -> None:
    """What `--path` writes is checked against the fixture bytes, not against a previous run.

    The artifact is what `join_programs.py` and `verify_provenance.py` read, so its digest set has to be
    the one these tests just pinned; reading it back is also the only way to check that `--program`
    reaches every row as `store`, which is how a remainder names where a certificate came from.
    """
    bundle_path = tmp_path / "fixture.pem"
    want = digest_of(b"A")
    bundle_path.write_text(
        bundle(f"# Subject: CN=Written Test Root\n{fingerprint_lines(want)}"),
        encoding="utf-8",
    )

    argv = [
        "collect_bundle.py",
        "--data",
        str(tmp_path),
        "--program",
        "fixture.written",
        "--path",
        str(bundle_path),
    ]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", argv)
        assert collect_bundle.main() == 0

    doc = json.loads((tmp_path / "store" / "fixture.written.json").read_text("utf-8"))
    rows = doc["certificates"]
    assert [r["sha256"] for r in rows] == [want]
    assert rows[0]["der_octets"] == len(synthetic_der(b"A"))
    assert rows[0]["subject"] == "CN=Written Test Root"
    assert rows[0]["store"] == "fixture.written"
    assert rows[0]["bundle_fingerprint_agrees"] is True
    assert doc["counts"]["pem_blocks"] == 1
    assert doc["counts"]["fingerprint_checked"] == doc["counts"]["fingerprint_agrees"] == 1
    provenance = doc["provenance"]
    assert provenance["path"] == str(bundle_path)
    assert provenance["file_sha256"] == hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    # The hashes-and-counts posture, stated by the artifact itself rather than only by this file's prose.
    assert "no subject" in provenance["note"]


def test_membership_is_diffed_between_runs(tmp_path: Path) -> None:
    """`ta.collect_bundle`: a second run over the same program records what joined and what left.

    The artifact path is keyed by program, so the second run writes over the first; the diff is what keeps
    the superseded membership recoverable (current - added + removed) and names the file it superseded by
    its own SHA-256. A first run records that there was nothing to compare against, rather than calling every
    anchor "added", which would read as a program that grew from an empty trust set.
    """
    bundle_path = tmp_path / "fixture.pem"
    artifact = tmp_path / "store" / "fixture.diffed.json"
    argv = ("--data", str(tmp_path), "--program", "fixture.diffed", "--path", str(bundle_path))

    bundle_path.write_text(blocks((b"A", ""), (b"B", "")), encoding="utf-8")
    assert run_main(*argv) == 0
    first_bytes = artifact.read_bytes()
    first = json.loads(first_bytes)
    assert first["membership_change"]["previous"] is None
    assert "first run" in first["membership_change"]["note"]
    assert "added" not in first["membership_change"]

    bundle_path.write_text(blocks((b"B", ""), (b"C", ""), (b"D", "")), encoding="utf-8")
    assert run_main(*argv) == 0
    second = json.loads(artifact.read_text("utf-8"))
    change = second["membership_change"]

    assert change["comparable"] is True
    assert change["added"] == sorted([digest_of(b"C"), digest_of(b"D")])
    assert change["removed"] == [digest_of(b"A")]
    assert change["counts"] == {"added": 2, "removed": 1, "unchanged": 1}
    previous = change["previous"]
    assert previous["file_sha256"] == hashlib.sha256(first_bytes).hexdigest()
    assert previous["retrieved_at"] == first["retrieved_at"]
    assert previous["distinct_certificates"] == 2
    # The superseded membership is reconstructible from the artifact that replaced it.
    now = {r["sha256"] for r in second["certificates"]}
    assert (now - set(change["added"])) | set(change["removed"]) == {
        r["sha256"] for r in first["certificates"]
    }

    # An unchanged rerun diffs to nothing, and says so with counts rather than by omission.
    assert run_main(*argv) == 0
    third = json.loads(artifact.read_text("utf-8"))["membership_change"]
    assert third["counts"] == {"added": 0, "removed": 0, "unchanged": 3}
    assert third["added"] == third["removed"] == []


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        pytest.param(b"not json", "unreadable", id="not-json"),
        pytest.param(b'{"program": "fixture.diffed"}', "unreadable", id="no-certificates"),
        pytest.param(
            b'{"program": "other", "certificates": []}',
            "is for program 'other'",
            id="other-program",
        ),
    ],
)
def test_a_previous_artifact_that_cannot_be_compared_is_not_diffed_as_empty(
    tmp_path: Path, content: bytes, reason: str
) -> None:
    """A corrupt or foreign previous file is named and refused, never read as a program that trusted nothing."""
    previous = tmp_path / "store" / "fixture.diffed.json"
    previous.parent.mkdir()
    previous.write_bytes(content)

    change = collect_bundle.membership_change(previous, "fixture.diffed", {digest_of(b"A")})

    assert change["comparable"] is False
    assert reason in str(change["reason"])
    assert "added" not in change
    named = change["previous"]
    assert isinstance(named, dict)
    assert named["path"] == str(previous)
    assert named["file_sha256"] == hashlib.sha256(content).hexdigest()


def test_a_reader_that_prints_pem_yields_the_same_digests_as_a_file(tmp_path: Path) -> None:
    """`ta.readers_via_command`: node, keytool and python are read through one seam, so the seam is pinned.

    The whole join rests on every program's digest coming from the same code. A reader path that hashed
    differently from a file path would manufacture disagreement between two programs that ship the very
    same anchor, so both routes are run over identical bytes here and compared.
    """
    text = bundle("# Subject: CN=Reader Test Root\n")
    bundle_path = tmp_path / "reader-fixture.pem"
    bundle_path.write_text(text, encoding="utf-8")

    from_file, _ = collect_bundle.index_pem(
        bundle_path.read_text(encoding="utf-8"), program="fixture.reader"
    )
    reader = tmp_path / "print_pem.py"
    # argv is passed as a list and never through a shell; the script prints PEM on stdout and nothing else.
    reader.write_text(
        "import sys\nsys.stdout.write(open(sys.argv[1], encoding='utf-8').read())\n",
        encoding="utf-8",
    )
    argv = [
        "collect_bundle.py",
        "--data",
        str(tmp_path),
        "--program",
        "fixture.reader",
        "--reader",
        sys.executable,
        f"--reader-arg={reader}",
        f"--reader-arg={bundle_path}",
    ]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", argv)
        assert collect_bundle.main() == 0

    doc = json.loads((tmp_path / "store" / "fixture.reader.json").read_text("utf-8"))
    assert {r["sha256"] for r in doc["certificates"]} == set(from_file)

    provenance = doc["provenance"]
    assert provenance["reader"] == [sys.executable, str(reader), str(bundle_path)]
    assert provenance["pem_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
    # A reader names nothing it cannot name: the argv is retained so the claim is re-runnable.
    assert "reader" in provenance["method"]


def test_a_reader_that_will_not_speak_writes_no_artifact(tmp_path: Path) -> None:
    """A refusal leaves the data directory alone rather than writing an empty trust set.

    An artifact with zero certificates and a green exit would read as "this program trusts nothing" — the
    most misleading thing this pipeline could publish, and one `--only` sweep away from happening.
    """
    argv = [
        "collect_bundle.py",
        "--data",
        str(tmp_path),
        "--program",
        "fixture.refuses",
        "--reader",
        sys.executable,
        # Joined by `=` (row `ta.reader_arg_form`): as two words argparse takes `-c` for an option.
        "--reader-arg=-c",
        "--reader-arg=import sys; sys.stderr.write('no keystore here'); raise SystemExit(2)",
    ]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", argv)
        assert collect_bundle.main() == 1

    assert not (tmp_path / "store" / "fixture.refuses.json").exists()
    assert not (tmp_path / "store").exists()


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "collect_bundle.py"


def interpreter(version: str | None) -> list[str]:
    """argv for the interpreter under test: this one, or `py -<version>` when the launcher has it."""
    if version is None:
        return [sys.executable]
    launcher = shutil.which("py")
    if launcher is None:
        pytest.skip("no `py` launcher on this host")
    probe = subprocess.run(  # noqa: S603 - argv is a list; the launcher came from shutil.which
        [launcher, f"-{version}", "-c", "pass"], capture_output=True, timeout=60
    )
    if probe.returncode != 0:
        pytest.skip(f"`py -{version}` is not installed on this host")
    return [launcher, f"-{version}"]


@pytest.mark.parametrize("version", [None, "3.12"], ids=["this-python", "py-3.12"])
def test_a_reader_flag_reaches_the_reader_only_when_joined_by_equals(
    tmp_path: Path, version: str | None
) -> None:
    """`ta.reader_arg_form`, run as a process under this interpreter and under 3.12.

    The row's claim is that `--reader-arg -c` is refused by argparse on 3.12 as well as on 3.14, so it is
    not a regression of one release: the two-word spelling exits 2 and writes nothing, and the `=` spelling
    hands `-c` to the reader, whose PEM is then hashed like any file's.
    """
    pem_text = bundle("# Subject: CN=Dash Test Root\n")
    code = f"import sys; sys.stdout.write({pem_text!r})"
    base = [
        *interpreter(version),
        str(SCRIPT),
        "--data",
        str(tmp_path),
        "--program",
        "fixture.dash",
        "--reader",
        sys.executable,
    ]
    artifact = tmp_path / "store" / "fixture.dash.json"

    split = subprocess.run(  # noqa: S603 - argv is a list built from this test's own paths
        [*base, "--reader-arg", "-c", "--reader-arg", code],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert split.returncode == 2, split.stderr
    assert "--reader-arg" in split.stderr
    assert not artifact.exists()

    joined = subprocess.run(  # noqa: S603 - argv is a list built from this test's own paths
        [*base, "--reader-arg=-c", f"--reader-arg={code}"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert joined.returncode == 0, joined.stderr
    doc = json.loads(artifact.read_text("utf-8"))
    assert [r["sha256"] for r in doc["certificates"]] == [digest_of(b"A")]
    assert doc["provenance"]["reader"] == [sys.executable, "-c", code]


def test_the_help_says_how_to_pass_a_reader_flag() -> None:
    """The form is documented where a caller looks for it, not only in the roadmap."""
    done = subprocess.run(  # noqa: S603 - argv is a list: this interpreter and the script under test
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0
    assert "--reader-arg=-c" in done.stdout


# --- PEM armour: boundaries and hostile input -----------------------------------------------------


def test_lowercase_begin_boundary_is_not_a_block() -> None:
    """Encapsulation boundaries are case-sensitive (RFC 7468 erratum 4508, verified), so this is no block.

    The lowercase block is also not allowed to name the real block below it: its base64 lines have letters
    and no `key:` prefix, which is exactly what the unkeyed-comment fallback would otherwise take.
    """
    lowered = pem_for(b"A").replace(BEGIN, BEGIN.lower()).replace(END, END.lower())
    text = f"{lowered}\n{pem_for(b'B')}\n"

    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["pem_blocks"] == 1
    assert counts["malformed_blocks"] == 0
    assert set(seen) == {digest_of(b"B")}
    assert entry(seen, b"B")["subject"] is None
    assert entry(seen, b"B")["alias"] is None


@pytest.mark.parametrize("label", ["X509 CERTIFICATE", "X.509 CERTIFICATE"])
def test_a_legacy_label_is_counted_and_warned_about_but_never_hashed(
    tmp_path: Path, label: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """`ta.pem_armour`: RFC 7468 section 5.1 says parsers SHOULD NOT treat these labels as "CERTIFICATE".

    The same section allows a backwards-compatible exception "potentially together with a warning"; this
    collector takes the strict reading for the digest set and the lenient one for the run: the block is
    counted and warned about, its bytes never become a digest, and the bundle around it is still read. Its
    base64 lines must not name the real block below it either.
    """
    legacy = pem_for(b"A").replace("BEGIN CERTIFICATE", f"BEGIN {label}")
    legacy = legacy.replace("END CERTIFICATE", f"END {label}")
    text = f"# Subject: CN=Legacy\n{legacy}\n{pem_for(b'B')}\n"

    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["legacy_label_blocks"] == 1
    assert set(seen) == {digest_of(b"B")}
    assert entry(seen, b"B")["subject"] is None
    assert counts["pem_blocks"] == counts["distinct_certificates"] == 1
    assert counts["malformed_blocks"] == 0

    bundle_path = tmp_path / "legacy.pem"
    bundle_path.write_text(text, encoding="utf-8")
    assert (
        run_main("--data", str(tmp_path), "--program", "fixture.legacy", "--path", str(bundle_path))
        == 0
    )
    assert "legacy" in capsys.readouterr().err
    doc = json.loads((tmp_path / "store" / "fixture.legacy.json").read_text("utf-8"))
    assert doc["counts"]["legacy_label_blocks"] == 1
    assert [r["sha256"] for r in doc["certificates"]] == [digest_of(b"B")]


def test_a_conforming_bundle_reports_no_legacy_label_and_no_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle_path = tmp_path / "plain.pem"
    bundle_path.write_text(bundle("", ""), encoding="utf-8")
    assert (
        run_main("--data", str(tmp_path), "--program", "fixture.plain", "--path", str(bundle_path))
        == 0
    )
    assert "legacy" not in capsys.readouterr().err
    doc = json.loads((tmp_path / "store" / "fixture.plain.json").read_text("utf-8"))
    assert doc["counts"]["legacy_label_blocks"] == 0


def ten_megabytes_of_base64() -> str:
    line = "QUFB" * 16  # 64 columns of valid base64
    return "\n".join([line] * (10 * 1024 * 1024 // 65 + 1))


@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param(lambda: f"{BEGIN}\n{ten_megabytes_of_base64()}\n{END}\n", id="10mb-of-base64"),
        pytest.param(lambda: pem_for(b"Z").replace("\n", "\n\x00", 2) + "\n", id="nul-in-body"),
        pytest.param(lambda: f"{BEGIN}\n\x00\x00\x00\n{END}\n", id="only-nul"),
        pytest.param(lambda: f"{BEGIN}\n{END}\n", id="empty-block"),
        pytest.param(
            lambda: pem_for(b"Z").rpartition("\n")[0] + "\n",
            id="unterminated-before-the-next-block",
        ),
        pytest.param(lambda: f"{BEGIN}\n{ten_megabytes_of_base64()}\n", id="unterminated-10mb"),
    ],
)
def test_hostile_input_ends_in_an_error_count_never_a_crash(hostile: Any) -> None:
    """`ta.pem_armour`'s hostile cases: each is one counted malformed block, and its neighbours survive.

    A good block sits on either side, so the case also proves the damage stays inside its own region.
    """
    text = f"{pem_for(b'A')}\n{hostile()}{pem_for(b'B')}\n"

    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert counts["pem_blocks"] == 3
    assert counts["malformed_blocks"] == 1
    assert set(seen) == {digest_of(b"A"), digest_of(b"B")}
    assert (
        counts["distinct_certificates"] + counts["duplicate_blocks"] + counts["malformed_blocks"]
        == counts["pem_blocks"]
    )


def test_an_unterminated_block_at_the_end_of_the_file_is_counted() -> None:
    """A truncated download: the last block never reaches its END marker, so it is no digest."""
    text = pem_for(b"A") + "\n" + pem_for(b"B").rpartition("\n")[0]

    seen, counts = collect_bundle.index_pem(text, program="fixture")

    assert (counts["pem_blocks"], counts["malformed_blocks"]) == (2, 1)
    assert set(seen) == {digest_of(b"A")}


def test_a_nul_in_a_header_is_carried_and_does_not_crash() -> None:
    seen, counts = collect_bundle.index_pem(
        bundle("# Subject: CN=Nul\x00Test Root\n"), program="fixture"
    )

    assert counts["distinct_certificates"] == 1
    assert entry(seen, b"A")["subject"] == "CN=Nul\x00Test Root"


def test_a_program_with_no_default_path_is_a_refusal_and_not_an_empty_bundle(
    tmp_path: Path,
) -> None:
    """`--program` without `--path` or `--url`: exit 1, because guessing a path would invent a store."""
    argv = [
        "collect_bundle.py",
        "--data",
        str(tmp_path),
        "--program",
        "gnu.tls",
    ]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", argv)
        assert collect_bundle.main() == 1

    assert collect_bundle.bundle_path("gnu.tls", None) is None
    assert not (tmp_path / "store").exists()


# --- the indexed bytes are retained under raw/ ----------------------------------------------------


def retained_digest_set(path: Path, program: str) -> set[str]:
    """Re-index a retained copy from scratch, the way `check_spki_artifact.py` will meet it."""
    seen, _ = collect_bundle.index_pem(
        path.read_text(encoding="utf-8", errors="replace"), program=program
    )
    return set(seen)


def test_path_mode_retains_the_bundle_it_indexed_with_its_digest(tmp_path: Path) -> None:
    """`--path` leaves raw/<program>.pem, byte-identical to the file it read, named in provenance.

    CRLF line endings are used on purpose: `read_text` folds them, so a copy written from the decoded text
    would hash differently from the source, and `file_sha256` would stop naming the file it names today.
    """
    source = tmp_path / "src" / "bundle.pem"
    source.parent.mkdir()
    source.write_bytes(
        bundle("# Subject: CN=Kept A\n", "# Subject: CN=Kept B\n").replace("\n", "\r\n").encode()
    )
    data = tmp_path / "data"
    assert run_main("--data", str(data), "--program", "fixture.kept", "--path", str(source)) == 0

    raw = data / "raw" / "fixture.kept.pem"
    assert raw.read_bytes() == source.read_bytes()
    assert not raw.with_name(raw.name + ".partial").exists()
    doc = json.loads((data / "store" / "fixture.kept.json").read_text("utf-8"))
    provenance = doc["provenance"]
    assert provenance["path"] == str(source)
    assert provenance["cached_at"] == str(raw)
    assert provenance["file_sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert retained_digest_set(raw, "fixture.kept") == {r["sha256"] for r in doc["certificates"]}
    assert retained_digest_set(raw, "fixture.kept") == {digest_of(b"A"), digest_of(b"B")}


def test_reader_mode_retains_stdout_exactly_and_it_reindexes_to_the_artifact(
    tmp_path: Path,
) -> None:
    """`--reader` leaves the reader's stdout as raw/<program>.pem, so `python.schannel` can be re-read.

    The reader here is the registry row's shape: this interpreter with `--reader-arg=-c` and code that
    prints `# Subject:` lines and PEM. The retained digest equals `pem_sha256`, because both are the hash of
    the one text that was indexed.
    """
    text = bundle("# Subject: CN=Reader Kept A\n", "# Subject: CN=Reader Kept B\n")
    code = f"import sys; sys.stdout.write({text!r})"
    assert (
        run_main(
            "--data",
            str(tmp_path),
            "--program",
            "fixture.readkept",
            "--reader",
            sys.executable,
            "--reader-arg=-c",
            f"--reader-arg={code}",
        )
        == 0
    )

    raw = tmp_path / "raw" / "fixture.readkept.pem"
    assert raw.read_bytes() == text.encode("utf-8")
    doc = json.loads((tmp_path / "store" / "fixture.readkept.json").read_text("utf-8"))
    provenance = doc["provenance"]
    assert provenance["reader"] == [sys.executable, "-c", code]
    assert provenance["cached_at"] == str(raw)
    assert provenance["file_sha256"] == provenance["pem_sha256"]
    assert provenance["file_sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    digests = {r["sha256"] for r in doc["certificates"]}
    assert digests == {digest_of(b"A"), digest_of(b"B")}
    assert retained_digest_set(raw, "fixture.readkept") == digests
    assert doc["counts"]["subject_named"] == 2


def test_a_retained_copy_that_does_not_reindex_refuses_the_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the copy under raw/ would not reproduce the digest set, neither it nor the artifact is written."""
    source = tmp_path / "bundle.pem"
    source.write_text(bundle("# Subject: CN=Refused\n"), encoding="utf-8")
    monkeypatch.setattr(collect_bundle, "retained_digests", lambda *_a, **_k: set())
    argv = (
        "--data",
        str(tmp_path / "data"),
        "--program",
        "fixture.mismatch",
        "--path",
        str(source),
    )
    assert run_main(*argv) == 1

    assert not (tmp_path / "data" / "store").exists()
    assert list((tmp_path / "data" / "raw").iterdir()) == []


def test_the_reindex_check_uses_the_indexer_it_checks(tmp_path: Path) -> None:
    """`retained_digests` agrees with `index_pem` for a plain file and for an archive."""
    plain = tmp_path / "plain.pem"
    plain.write_bytes(blocks((b"A", ""), (b"B", "")).replace("\n", "\r\n").encode())
    assert collect_bundle.retained_digests(plain, program="p", name_key="subject") == {
        digest_of(b"A"),
        digest_of(b"B"),
    }
    archive = tmp_path / "files.tar.gz"
    archive.write_bytes(tar_payload({"a.0": aosp_member(b"C", "CN=C")}))
    assert collect_bundle.retained_digests(archive, program="p", name_key="alias", tar=True) == {
        digest_of(b"C")
    }


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


def test_url_mode_is_unchanged_by_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--url` keeps writing raw/<program>.pem itself, with the same provenance keys as before."""
    payload = bundle("# Subject: CN=Fetched\n").encode("utf-8")
    monkeypatch.setattr(
        collect_bundle.urllib.request, "urlopen", lambda *_a, **_k: _Response(payload)
    )
    url = "https://example.invalid/cacert.pem"
    assert run_main("--data", str(tmp_path), "--program", "fixture.url", "--url", url) == 0

    raw = tmp_path / "raw" / "fixture.url.pem"
    assert raw.read_bytes() == payload
    assert sorted(p.name for p in (tmp_path / "raw").iterdir()) == ["fixture.url.pem"]
    doc = json.loads((tmp_path / "store" / "fixture.url.json").read_text("utf-8"))
    provenance = doc["provenance"]
    assert set(provenance) == {"url", "cached_at", "file_sha256", "method", "note"}
    assert provenance["url"] == url
    assert provenance["cached_at"] == str(raw)
    assert provenance["file_sha256"] == hashlib.sha256(payload).hexdigest()
    assert [r["sha256"] for r in doc["certificates"]] == [digest_of(b"A")]
