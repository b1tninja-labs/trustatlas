# What trustatlas can say, and what it cannot yet say

This is the roadmap for the supply chain of trust anchors: every obligation the site could plausibly take
on, with an honest status against the tree at `HEAD`. The north star is the question "which certificates has
some globally trusted program issued, and how do we know?" — and a row that overstates coverage turns that
into marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the behaviour regressed.
`trustatlas` has no test suite, so **no row here reads `[ok]`**, and none may be promoted until a test
exists to defend it. Landed tools therefore read `[part]`: the code runs and its artifact is the evidence,
but nothing re-checks the claim when the tool changes.

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is missing stated --
`[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. `AGENTS.md` governs what may be added
here; `PLAN.md`'s gating rule and its **Unverified** section bind this document and are not summarised away.

## 1. Collectors

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `ta.probe_sources` | PLAN.md §Where each collector runs | `[part]` | `tools/probe_sources.py` — writes `sources/catalog.json` under the `--data` directory (host `M:\trustatlas`, container `/data`), never into this repository; no test, so a `--only` sweep that moved `catalog.json` mid-run is undetected. Test: `tests/test_probe_sources.py::test_committed_catalog_rehashes_to_its_recorded_digests` (to be written) | P1 |
| `ta.collect_certdata` | Mozilla program list, HTTPS | `[part]` | `tools/collect_certdata.py` — container-resident; provenance fields carried, but no assertion that a fetch produced the expected anchor count. Test: `tests/test_collect_certdata.py::test_fetch_yields_the_expected_anchor_count` (to be written) | P3 |
| `ta.collect_bundle` | curl bundle, HTTPS | `[part]` | `tools/collect_bundle.py --url` — takes `--url` because the image has no `certifi`; hash and count recorded, membership not diffed between runs. **The split-and-hash path is now `index_pem(text, program=, name_key=)`, imported by `collect_java.py` rather than copied**, because a join across programs is only meaningful if every digest comes from one implementation; the refactor was checked by re-reading `raw/curl.pem` and joining the result against the recorded artifact — `118 vs 118, shared 118, identical certificate sets` — which is a manual check, so the row stays `[part]`. Test: `tests/test_collect_bundle.py::test_membership_is_diffed_between_runs` (to be written) | P2 |
| `ta.collect_store` | `Cert:\LocalMachine` on Windows | `[part]` | `tools/collect_store.py` — measured 68 `Root` / 52 `AuthRoot` / 0 `Disallowed` on 2026-11-06, exit 3 on non-Windows; a one-machine artifact with no re-derivation check. Test: `tests/test_collect_store.py::test_store_counts_rederive_from_the_artifact` (to be written) | P2 |
| `ta.collect_ctl` | MS-CAB, MS-CTL | `[part]` | `tools/collect_ctl.py` — fetches over plain HTTP, checks `MSCF`, pins `c0aa761f…`; reports `certificates_enumerated: 0`, `decoded: false`. Test: `tests/test_collect_ctl.py::test_cab_magic_and_pinned_digest_are_checked` (to be written) | - (unplaced) |
| `ta.join_programs` | PLAN.md §joins | `[part]` | `tools/join_programs.py` — joins on certificate SHA-256. Measured 2026-11-07 with `asn1core.spki_sha256`: certifi (120) × curl (118) share 114 certificates and **114 keys**, and none of the 6 certifi-only or 4 curl-only certificates shares a key across the two, so for bundles the certificate key is not lying. Artifacts carry hashes and counts only (no DER is retained pending `cl.aup-review`), so a key-level join cannot be reproduced from them. **Added 2026-11-07: `--a-trust` / `--b-trust` restrict a side to the anchors a program trusts as delegators under one bit** (`SERVER_AUTH`), because the NSS artifact carries S/MIME and code-signing roots too and comparing them against a TLS store overstates the disagreement — filtering NSS to 117 rather than 169 moves the Java overlap from 76 to 59 and changes what the number means. The filter is recorded in the written artifact (`trust_filter`, `totals_before_filter`), since a stored join that silently filtered would lie later. The remainder listing now also names a keystore's `alias`, which it previously threw away in favour of a digest prefix. Test: `tests/test_join_programs.py::test_join_reproduces_from_committed_artifacts` (to be written) | P2 |
| `ta.compose_collect` | compose `collect` service | `[part]` | `compose.yaml` — executed with Docker 29.3.1; nothing asserts the three tools still succeed in the image. Test: `tests/test_compose_collect.py::test_the_three_tools_succeed_in_the_image` (to be written) | P2 |
| `ta.readers_remaining` | PLAN.md P2 | `[part]` | **Java read on 2026-11-07**: `tools/collect_java.py` asks the JDK's own `keytool -list -rfc` for `cacerts` — measured here on JDK 26.0.1: 109 anchors, 0 duplicate, 0 malformed, artifact `java.cacerts.json`. Java's keystore format stays Java's business, so no PKI is implemented here; what keytool prints as an alias is recorded as `alias` and `subject` stays absent, because an alias is a nickname and not a distinguished name. Joined against every program already recorded: NSS-as-TLS (117) × Java (109) = 59 shared and 50 Java-only; unfiltered NSS (169) = 76 shared; certifi (120) = 61; curl (118) = 59; Windows root store (68) = 43. **No pair is a subset of the other**, which is the correction recorded in `PLAN.md` §the two graphs. Still unread: Android, GnuTLS, OpenSSL-on-Linux distro stores, macOS `security trust-settings-export`. Test: `tests/test_collect_java.py::test_aliases_are_captured_and_subjects_stay_absent` (to be written) | P2 |

## 2. Derivation and index

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `ta.derive_issuer_edges` | RFC 5280 issuer/subject links | `[ ]` | owned by `pkix`; needs `asn1core` name encoding before an edge can be asserted rather than guessed | P3 |
| `ta.spki_key_identity` | SPKI SHA-256 | `[part]` | `asn1core` **shipped it**: `x509.spki_sha256`, pinned by `tests/test_x509_corpus.py::test_the_extracted_digests_match_an_independent_implementation` against digests `cryptography` printed for the same bytes. What remains is consumption: `trustatlas` tools are stdlib-only, so the key identity must arrive through an artifact or an `asn1core`-side tool, not a parser grown here. Test: `tests/test_spki_key_identity.py::test_key_identity_arrives_through_an_artifact` (to be written) | P2 |
| `ta.ctl_decode` | MS-CAB unpack, signed trust blob | `[ ]` | owned by `pkix`: `cab.member()`, `ctl.root_program()`, `ctl.signed_by_microsoft()`. Until those exist the Windows program is bytes and a pinned hash, not a membership count | P2, blocked on `pkix` M7 |
| `ta.coverage_index` | PLAN.md P4 | `[ ]` | owned by `certledger`; the index that makes coverage a queryable state rather than a paragraph | P4 |

## 3. Publication surface

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `ta.renderer` | PLAN.md gating rule | `[ ]` | gated: a section may display software behaviour only when the code behind it exists. BGP, RPKI and whois are deliberately not sections, because those projects raise `NotImplementedError` | P5 |
| `ta.render_blocklist` | `disallowedcertstl.cab` | `[ ]` | renders a pinned, dated Microsoft blocklist as an artifact view. Rendering is not authoring: the claim belongs to `keyproof` | P6 |
| `ta.publish_bundles` | program terms of use | `[ ]` | blocked on `cl.aup-review` in `certledger`. Until it rules, the posture is hashes-and-counts and no bundle is redistributed | none (gated on `cl.aup-review`) |
| `ta.provenance_fields` | PLAN.md provenance | `[part]` | written by every collector; nothing verifies that a re-run reproduces them, so a silent provenance loss would pass unnoticed. Test: `tests/test_provenance_fields.py::test_a_rerun_reproduces_every_provenance_field` (to be written) | P1 |

## 4. Deliberate non-goals

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `ta.protocol_logic` | PKI parsing | `[no]` | `AGENTS.md`: parsing anchors is `asn1core`, path and issuer links `pkix`, CT `ctspy`, storage and coverage `certledger`, DANE and DNSSEC `namespy`. A second, laxer PKI here is the one thing a trust map cannot survive | - |
| `ta.live_oracle` | view-time fetching | `[no]` | the renderer reads committed artifacts; a page that fetches at view time cannot state what it saw when, and its absence claims come unanchored | - |
| `ta.compromise_claims` | `keyproof/PLAN.md` | `[no]` | this site renders a blocklist and never writes one, including its oracle problem | - |
| `ta.package` | `pyproject.toml`, PyPI | `[no]` | `tools/` holds stdlib-only scripts that write artifacts. Scaffolding a package ahead of its wave turns a plan into a shell nobody maintains | - |

## 5. Board projection

`py sdk-forge/sync_roadmap.py --project trustatlas --check` projects this matrix onto GitHub issues; the
issues are collected on Project V2 **#4 "Protocol SDK portfolio"**, the only board. Read with
`gh project item-list 4` on 2026-11-07: **20 items** from this repository, all in Backlog — 9 `status:partial`,
7 `status:unimplemented`, 4 `type:non-goal`, one per row of sections 1 to 4. The whole board held 102 items
across five repositories (`sdk-forge` 50, `trustatlas` 20, `pkix` 19, `ctspy` 7, `certledger` 6).

This section is a dated snapshot, not a live count. The board is the live view; neither is the source of
truth. **This file is**, and a board cannot enforce a rule — only a test can.

The `Milestone` column places each row on `PLAN.md`'s P0-P7 phasing. A `Test:` id marked `(to be written)`
names the test that would let the row move past `[part]`; no such file exists, because `trustatlas` has no
test suite yet.

## 6. Open questions

- **Cross-sign reach has no row.** `PLAN.md` P6 and its design goal (formerly `ta.reach`: reach computed via
  `pkix`, not by hand) are not carried by any row above. Whether that is a new row or part of
  `ta.render_blocklist` is undecided, so no row was invented.
- **`ta.collect_ctl` has no phase.** It fetches the Microsoft program that P2 is about, but decoding it waits on
  `pkix` M7 (`ta.ctl_decode`); P2 is the likely placement and is not asserted here.
