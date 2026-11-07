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

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `ta.probe_sources` | PLAN.md §Where each collector runs | `[part]` | `tools/probe_sources.py` — writes `sources/catalog.json`; no test, so a `--only` sweep that moved `catalog.json` mid-run is undetected |
| `ta.collect_certdata` | Mozilla program list, HTTPS | `[part]` | `tools/collect_certdata.py` — container-resident; provenance fields carried, but no assertion that a fetch produced the expected anchor count |
| `ta.collect_bundle` | curl bundle, HTTPS | `[part]` | `tools/collect_bundle.py --url` — takes `--url` because the image has no `certifi`; hash and count recorded, membership not diffed between runs |
| `ta.collect_store` | `Cert:\LocalMachine` on Windows | `[part]` | `tools/collect_store.py` — measured 68 `Root` / 52 `AuthRoot` / 0 `Disallowed` on 2026-11-06, exit 3 on non-Windows; a one-machine artifact with no re-derivation check |
| `ta.collect_ctl` | MS-CAB, MS-CTL | `[part]` | `tools/collect_ctl.py` — fetches over plain HTTP, checks `MSCF`, pins `c0aa761f…`; reports `certificates_enumerated: 0`, `decoded: false` |
| `ta.join_programs` | PLAN.md §joins | `[part]` | `tools/join_programs.py` — joins on certificate SHA-256. Measured 2026-11-07 with `asn1core.spki_sha256`: certifi (120) × curl (118) share 114 certificates and **114 keys**, and none of the 6 certifi-only or 4 curl-only certificates shares a key across the two, so for bundles the certificate key is not lying. Artifacts carry hashes and counts only (no DER is retained pending `cl.aup-review`), so a key-level join cannot be reproduced from them |
| `ta.compose_collect` | compose `collect` service | `[part]` | `compose.yaml` — executed with Docker 29.3.1; nothing asserts the three tools still succeed in the image |
| `ta.readers_remaining` | PLAN.md P2 | `[ ]` | unread programs: Android, Java, GnuTLS, OpenSSL-on-Linux distro stores, macOS `security trust-settings-export` |

## 2. Derivation and index

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `ta.derive_issuer_edges` | RFC 5280 issuer/subject links | `[ ]` | owned by `pkix`; needs `asn1core` name encoding before an edge can be asserted rather than guessed |
| `ta.spki_key_identity` | SPKI SHA-256 | `[part]` | `asn1core` **shipped it**: `x509.spki_sha256`, pinned by `tests/test_x509_corpus.py::test_the_extracted_digests_match_an_independent_implementation` against digests `cryptography` printed for the same bytes. What remains is consumption: `trustatlas` tools are stdlib-only, so the key identity must arrive through an artifact or an `asn1core`-side tool, not a parser grown here |
| `ta.ctl_decode` | MS-CAB unpack, signed trust blob | `[ ]` | owned by `pkix`: `cab.member()`, `ctl.root_program()`, `ctl.signed_by_microsoft()`. Until those exist the Windows program is bytes and a pinned hash, not a membership count |
| `ta.coverage_index` | PLAN.md P4 | `[ ]` | owned by `certledger`; the index that makes coverage a queryable state rather than a paragraph |

## 3. Publication surface

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `ta.renderer` | PLAN.md gating rule | `[ ]` | gated: a section may display software behaviour only when the code behind it exists. BGP, RPKI and whois are deliberately not sections, because those projects raise `NotImplementedError` |
| `ta.render_blocklist` | `disallowedcertstl.cab` | `[ ]` | renders a pinned, dated Microsoft blocklist as an artifact view. Rendering is not authoring: the claim belongs to `keyproof` |
| `ta.publish_bundles` | program terms of use | `[ ]` | blocked on `cl.aup-review` in `certledger`. Until it rules, the posture is hashes-and-counts and no bundle is redistributed |
| `ta.provenance_fields` | PLAN.md provenance | `[part]` | written by every collector; nothing verifies that a re-run reproduces them, so a silent provenance loss would pass unnoticed |

## 4. Deliberate non-goals

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `ta.protocol_logic` | PKI parsing | `[no]` | `AGENTS.md`: parsing anchors is `asn1core`, path and issuer links `pkix`, CT `ctspy`, storage and coverage `certledger`, DANE and DNSSEC `namespy`. A second, laxer PKI here is the one thing a trust map cannot survive |
| `ta.live_oracle` | view-time fetching | `[no]` | the renderer reads committed artifacts; a page that fetches at view time cannot state what it saw when, and its absence claims come unanchored |
| `ta.compromise_claims` | `keyproof/PLAN.md` | `[no]` | this site renders a blocklist and never writes one, including its oracle problem |
| `ta.package` | `pyproject.toml`, PyPI | `[no]` | `tools/` holds stdlib-only scripts that write artifacts. Scaffolding a package ahead of its wave turns a plan into a shell nobody maintains |

## 5. Board projection

`py sdk-forge/sync_roadmap.py --project trustatlas --check` projects this matrix onto GitHub issues; the
issues are collected on Project V2 **#2 "Protocol SDK portfolio"**. Read back through the hosted GitHub MCP
server on 2026-11-07: **20 items** from this repository, all open — 8 `status:partial`, 8
`status:unimplemented`, 4 `type:non-goal`. The whole board held 42 items across four repositories, cross-checked
against GraphQL `items.totalCount`.

This section is a dated snapshot, not a live count. The board is the live view; neither is the source of
truth. **This file is**, and a board cannot enforce a rule — only a test can.


