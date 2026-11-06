# trustatlas: the supply chain of trust anchors

Status: **P1 landed 2026-11-05; the rest is still a plan.** `tools/probe_sources.py` generates the source catalog,
`Dockerfile` + `compose.yaml` run it, and artifacts live in `M:\trustatlas`. Still unbuilt: the readers (P2), the
derivation edges (P3), the index (P4, owned by `certledger`), and the renderer. `AGENTS.md` governs what may be
added here. No `package.json`, no PyPI, no protocol logic.

## What P1 measured

`docker compose run --rm probe` and a host run of the same script both reported **13 of 18 sources available**.
Comparing the two catalogs by content hash — which is the P1 exit test — found 11 identical and **2 differing:
`debian.ca_certificates` and `android.aosp.files`**. Those won their slot by returning 200 on an HTML directory
listing, whose bytes change every request. Three things follow, and they are the actual output of P1:

- **Availability is not fitness, and fitness is not stability.** A source is evidence only if the same URL yields
  the same bytes. `sources` entries whose content type is HTML are pages about a store, not the store.
- The catalog therefore carries a **stability verdict obtained by fetching twice**, or it silently launders web
  pages into artifacts. `ta.stability` landed the same day: the sweep now reports **13 available, 11 stable**, and
  flags exactly `android.aosp.files` and `debian.ca_certificates` as VOLATILE. A source is evidence only if the
  same URL yields the same bytes twice.
- The six URLs I had written by hand were wrong in a specific way: **NSS `certdata.txt` was a branch-name
  mistake** — the mirror's branch is `MAIN`, and the file is 1,356,175 bytes. `openjdk.cacerts`, the CCADB
  cross-program report and RIPE/APNIC/LACNIC TALs still have no working URL: four known-gaps, deliberately left
  as gaps rather than papered over with a substitute that answers 200 for something else.

One incidental measurement worth keeping: **curl's `cacert.pem` and `certifi`'s bundle each carry 118 PEM blocks
while CCADB's Mozilla included bundle carries 169.** That 51-root gap is exactly the kind of thing the derivation
view (P3) exists to explain rather than assert.


**Name.** **Ratified 2026-11-05.** Measured with `sdk-forge/names.py --index` against the 931,439-name
snapshot: `trustatlas` — **free on both signals, zero names one keystroke away**. `anchoratlas`, `rootstore` and
`trustsurvey` also pass and stand as fallbacks. Rejected: **`trustscope` is TAKEN** (v0.0.1, 2026-02-23,
"TrustScope — AI Agent Governance Platform"), and `anchormap`, `trustmap` and `caatlas` each sit one keystroke
from a live name (`anchorman`, `trustmcp`, `chatlas`) and so fail the rule that cost `derkit` its name. Ratified
for internal use and for the repository directory; **it is not cleared for publication**, because the checker
covers package indexes and nothing here has looked for a same-named project on the web.

## The idea

Draw how trust actually reaches a client. Not "which certificates exist" — CT covers that as far as it can —
but **which roots each store contains, where those lists came from, and through which cross-sign a key the
world never vetted ends up inside a store that trusts it anyway.**

The October 2026 eMudhra compromise is the argument for the picture. Eight intermediate keys became
recoverable from their own certificates. Six of the eight were TLS CAs and two were code-signing CAs, and each
of the eight carried **two** certificates: one under eMudhra's own roots, and one **cross-signed under
Comodo's `AAA Certificate Services`**. The cross-sign is why this was not an eMudhra-shaped incident: it
delivered compromised keys into trust stores that had never evaluated eMudhra. The affected party's own
guidance tells Android users to disable *AAA Certificate Services*, warning that doing so may break unrelated
sites. That is trust inheritance, in the wild, and no tool shows it.

Cross-signs are not an anomaly to explain away; they are structural. And the same structure makes most
"independent" trust stores into **copies of one list**: Debian's `ca-certificates`, curl's `cacert.pem`,
Python's `certifi`, Java's `cacerts` and a dozen runtime bundles all derive from Mozilla's NSS built-ins.
Anyone who can move a root in NSS has acted on clients Mozilla does not ship.

So this artifact is a map of **two graphs** that nobody puts together: the derivation graph among stores (who
copies whom, verified by hashing rather than asserted), and the issuance graph among certificates (which key
is trusted via which issuer, cross-signs included). Overlay the second on the first and you get the only
question that matters during an incident: *how many clients still reach this key, and by which path?*

## What exists, and the specific hole

| Instrument | What it does | What it cannot do |
| --- | --- | --- |
| CCADB | Per-program inclusion records and trust bits — the source of truth for root-program decisions | Not a derivation graph; blind to the stores that merely copy a bundle |
| `crt.sh`, Censys | Certificate search over logged issuance | It is an identity search. See `certledger/INCIDENT-CT-FORENSICS.md`: it cannot answer "what did this key issue" completely, and code-signing sits outside CT entirely |
| Browser `about:certificate`, OS UIs | Inspect the one chain you are holding | No comparison across stores, no lineage, no blocklist reach |
| Per-client probes | Indicate whether one client rejects one certificate | Ambiguous by construction: a network failure looks like a rejected certificate |

The hole is the **join**: one key, across stores, programs, bundles and incidents.

Measured locally on 2026-11-05 on a patched Windows box: `Cert:\LocalMachine\Root` holds **68** anchors,
`Cert:\LocalMachine\Disallowed` holds **0** — this machine carries no eMudhra block. The incident page asks a
user to open a URL and *infer* from an error page whether they are patched, and its own footnote admits the
ambiguity. Reading the store answers the same question **definitively and offline**, and it reaches exactly the
cases a TLS probe cannot: code-signing anchors, intercepting proxies, and runtimes shipping their own bundle.
That local audit is the most useful tool in this plan and the cheapest.

## Design goals

1. **Every rendered claim names its evidence** — a fixture and a test, or a provenance record naming the command
   that produced it. No assertion without a reproducible artifact.
2. **The renderer has no opinions and no network.** It displays artifacts; what it cannot show from the bytes it
   was given, it states it cannot show.
3. **SPKI SHA-256 is the join key**, so stores that spell one subject differently still align. This is the same
   predicate the incident work used (`issuer_key_hash` is the SHA-256 of the issuer's SPKI DER, RFC 6962
   section 3.2 paragraph 8), so analysis and map share one primitive.
4. **Derivation edges are verified, not asserted.** "`cacert.pem` ⊂ NSS built-ins" is a statement about hash
   sets: either it is true or the artifact shows drift. An edge that fails to reproduce is a finding.
5. **Freshness is visible.** Every store view carries `retrieved_at`. An old map is labelled old, never silent.
6. **Coverage is graded, not counted.** Absence is stated together with the set of stores actually examined, per
   TRUST-MODEL I5 and I7.
7. **The certificate index answers with its coverage.** A query returns rows, the logs consulted, the tree sizes
   and heads those answers came from, and the unfetchable ranges — because an empty result that cannot say which
   of four meanings it has is the incumbent's worst defect, and reproducing it here would be the actual failure.

## Non-goals

- **Not a protocol library.** No wire formats, no parsers invented here, no validation logic. `asn1core` parses,
  `pkix` validates, `ctspy` understands CT, `certledger` stores evidence. If the pipeline needs a capability
  those lack, it becomes an obligation *there* — which is the point of writing this down.
- **Not a race with `crt.sh` on breadth.** Being a bigger index than a free incumbent with a decade of
  backfill is not a winning axis, and the incumbent is not going away. The index in this plan competes on
  *availability, cost per query, and honest coverage* — see "The index is a prerequisite" below — and it is a
  prerequisite for the analyses, not the point of them.
- **Not `keyproof`.** The register of demonstrated key compromise, its oracle problem and its
  possession-versus-use distinction belong to `keyproof/PLAN.md`. `trustatlas` **renders** a blocklist; it never
  authors one.
- **Not a claim about "every certificate"** — declined as unachievable in `PORTFOLIO.md` section 5, because CT
  cannot see unlogged issuance and code-signing is not in CT at all.
- **Not a hosted service on day one.** A static build over committed artifacts comes first.

## Architecture

Three layers, with the boundary drawn so the interesting failures happen in the middle, where they are testable.

```
fetchers (python, tools/)                normalised artifacts (data/)            renderer (vite + react)
  one script per source          ──►       anchors / stores / edges       ──►      views, no logic
  emits bytes + provenance                  + provenance per artifact
```

**Fetchers.** A script per source that writes the raw bytes *and* a normalised summary, and refuses to write if
it cannot state where the bytes came from. `certledger/tools/corpus.py` is the pattern to copy: it will not
write a window until every entry in it verifies, and it keeps positions next to the bytes so nothing has to be
believed.

**Provenance contract.** Each artifact carries `source` (URL or absolute local path), `retrieved_at`, `sha256`
of the raw bytes, `bytes`, `parser` (project plus commit), and `command` — the literal invocation that
reproduces it. This is `ctspy/tools/fetch_evidence.py inclusion_sweep()`'s rule: evidence names a command that
exists. An artifact whose recorded command no longer reproduces its bytes is a bug in this repository.

**Schema, minimally.**

```
anchor   { spki_sha256, sha256, subject, serial, not_before, not_after, key_alg, notes }
store    { id, kind: program|os|distro|bundle|runtime|local, upstream, anchors[], retrieved_at, provenance }
edge     { kind: derives_from|cross_sign|included_by, from, to, evidence, verified: bool }
incident { spki_sha256[], reason, dates, source }          # rendered, never authored here
```

`edge.verified` matters more than `edge.kind`. A derivation edge is *computed* by intersecting hash sets; a
cross-sign edge is *read* from a certificate's issuer link. Neither may be typed by hand.

**Gating rule, applied to the site itself** (the same discipline as `cl.claims-discipline`). A section may show
software behaviour only when the code behind it exists. Trust anchors, CT evidence and DNSSEC are eligible:
`asn1core` and `namespy` are implemented, and `ctspy` verified against 23 operational logs. **BGP, RPKI, RTR,
whois and leases are not**: `PORTFOLIO.md` section 3 records that the 28 SDK shells raise `NotImplementedError`
with zero protocol behaviour. A portal of unwritten tools is precisely the failure mode section 7 names, so
those subjects stay off the map, or share one page plainly titled as plans.

## The index is a prerequisite, and the honest version of the crt.sh argument

Every analysis this project wants to perform — cross-sign reach, anchor lineage, "what did these keys issue" —
needs the same thing: **a local, queryable index over CT's contents.** It is not a side feature and it is not
optional; `certledger/INCIDENT-CT-FORENSICS.md` established that a log cannot be asked whether it holds a
certificate, because a v1 tree leaf commits to the log's own submission timestamp, so issuance questions are
answerable *only from a store*. Whatever the UI does later, the store is the work.

The incumbent's failure is measured, not remembered. During the November 2026 incident work, over fourteen
queries against `crt.sh`: **three returned HTTP 502**, a single JSON query took **24.8 s**, and the issuer HTML
view timed out at **24 s** without completing. Availability is one half of it.

The other half is the one nobody serves. On that instrument **an empty result is ambiguous**: it can mean "not
issued", "issued but not logged", "logged to a log you do not index", or "your query did not match the way you
thought it did". The incident work hit this twice. A control against the uncompromised sibling CA proved `q=`
does match issuers, which made the zeros mean something — and a second-level control then showed the children it
finds were themselves CA certificates, so the query has still never been demonstrated to surface forged *leaf*
certificates. Every confident sentence about CT absence has to survive that sequence, and no current tool will
let you survive it, because none of them publish coverage.

So the differentiated properties of the index, in priority order:

1. **Coverage travels with the answer.** Every result set carries which logs were consulted, to which tree size
   and under which signed head, and which ranges are `UNREACHABLE` / `BUDGET` / `EMPTY_WITHIN_TREE` /
   `CONFLICT`. Absence is reported as a graded state, never as an empty page. This is the existing
   `GapState` model applied to a query surface, and it is the whole thesis.
2. **Proof travels with the answer.** A row says "we have a record"; this should be able to say "log L signed a
   tree containing this leaf, here is the audit path and the head it was checked against". No CT browser does
   this. `ctspy` and `certledger` already can, across all 23 operational logs.
3. **Query by issuer key, not by spelling.** `crt.sh` matches names; the join key here is SPKI SHA-256 — the
   same predicate as `issuer_key_hash` — so a renamed or re-spelled CA cannot hide, and the eight compromised
   eMudhra keys are one query rather than a name guess per CA.
4. **Availability as an engineering target, not a wish.** The incident-driven design constraint is: immutable
   append-only segments built by the walk, no live fan-out to third parties at query time, and a degraded mode
   that answers from what it holds while stating what it lacks. crt.sh's failure shape — one huge mutable
   relational table behind arbitrary regex scans — is a choice, and it is avoidable at the cost of accepting
   staleness bounds instead of pretending queries are free.

**What it costs, stated before anyone commits.** The acquisition path is a full walk of every log ever usable,
including retired ones, at the per-request ceiling measured from this network: Google answers **32 entries per
`get-entries`** however many are asked for, and one Google log holds **874,621,301** entries (Nimbus2027, as
signed), so **~27M requests for that log alone** and the fleet total is orders of magnitude beyond a weekend.
Storage is billions of leaf records plus the DER or TBS bytes needed for issuer attribution. The arithmetic comes
from `certledger`'s own fixtures — 877,250,294 entries in the recorded Nimbus2027 head ÷ 32 per request =
**27,414,072 requests** for that log — and `certledger/ROADMAP.md` carried a "7.6 million" figure that neither
input supports, corrected the same day this document was written. Extended across the fleet, the total is orders
of magnitude beyond a weekend; so the index is gated on the same two things the walk always was: **the fetch
layer, and the anchor decision a named human owes**, plus a hosting choice. And the honest posture is
incremental: index the logs that matter for the analysis at hand, publish coverage, and let breadth grow with
budget rather than promising the world first.

## The index is one `certledger` obligation, not a new project

The store that makes search possible is already an obligation `certledger` carries: the deferred persistent entry
store, plus `cl.states`'s phase-3 wiring. Nothing needs to be invented for it and nothing should be built twice —
`certledger`'s row in the SDK table below is the same requirement stated once, and `trustatlas` consumes it
rather than competing with it.

## Views

1. **Certificate search — the substrate.** Query by SAN or common name, by issuer SPKI hash, by leaf fingerprint.
   Every result set answers three things besides the rows: which logs were consulted and to which tree size and
   head; what proportion of each log is actually walked; and whether any returned entry's inclusion is verified
   or merely recorded. Staleness is shown, not assumed.
2. **Store inventory** — count, kind, upstream, `retrieved_at`, plus key-algorithm and expiry histograms
   (expired anchors still shipping is real and findable).
3. **Membership matrix** — anchors × stores. The interesting cells are the lonely ones: a root in exactly one
   store, or in every store except one.
4. **Derivation graph** — which bundles are provably subsets of which, with drift surfaced as a diff rather
   than smoothed away.
5. **Cross-sign reach** — pick a key, see every store that trusts it and via which issuer. This is the eMudhra
   view, and the reason the project exists.
6. **Local audit** — dump this machine's stores and diff against a blocklist. Windows is enumerable today;
   macOS via `security trust-settings-export`; Linux by parsing the bundle and recording its hash.
7. **CT evidence**, later — render `certledger` windows and `ctspy` fleet fixtures with proof state visible per
   claim, so the page cannot overstate what was verified.

## Sources, as probed rather than recalled

Probed 2026-11-05: eight of fourteen candidates resolved and six did not, which is the entire reason this table
must be **generated by a probe on every run** instead of typed by someone who thinks they know the URLs.

| Source | Status | Shape |
| --- | --- | --- |
| `curl.se/ca/cacert.pem` | **200** | PEM bundle, Mozilla-derived |
| CCADB `IncludedCACertificateReportPEMCSV` | **200** | CSV with per-root trust bits and PEM |
| `android.googlesource.com/platform/system/ca-certificates` | **200** | one PEM per anchor, filename is the subject hash |
| `salsa.debian.org/debian/ca-certificates` | **200** | Debian packaging of the Mozilla bundle |
| `data.iana.org/root-anchors/root-anchors.xml` | **200** | DNSSEC KSK trust anchors |
| `iana.org/assignments/registrar-ids/registrar-ids.xml` | **200** | registrar identifiers |
| `www.gstatic.com/ct/log_list/v3/log_list.json` | **200** | CT logs, keys, MMD, state — already used by `certledger` |
| `apple.com/certificateauthority` | **200** | program page, not a machine-readable anchor set |
| NSS `certdata.txt` at the guessed raw path | **404** | path wrong; find the real one in the NSS tree |
| CCADB `CACertificatesCSVExport` | **404** | report name wrong; enumerate CCADB's report pages |
| `github.com/microsoft/winca` | **404** | repository name wrong; Microsoft's trusted-root material lives elsewhere |
| OpenJDK `cacerts` at the guessed raw path | **404** | path moved with the JDK restructure |
| RIPE NCC and ARIN RPKI TALs at guessed paths | **404** | both wrong; TALs live under each RIR's publishing paths |
| `Cert:\LocalMachine\Root` / `\Disallowed` | **local: 68 / 0** | authoritative for this machine, offline, no network |

Anything in a 404 row is a *to be discovered*, not a source. Its fetcher does not exist until the probe says 200
and the parser says how many anchors it read.

## What the SDKs must provide, which is the point of this document

The renderer is downstream. These are the obligations that unblock it, and each belongs to the project that owns
the concern — none of them get written here.

| Project | Needed | Why it belongs there |
| --- | --- | --- |
| `asn1core` | Read a PEM bundle, an NSS `certdata.txt` object sequence and a Windows export into `(subject, SPKI, serial, validity)` **from the stored bytes** — armour delivered 2026-11-05 (`dk.pem`); the `certdata.txt` reader is still owed | It is the only place that keeps original octets, which is what makes an SPKI hash trustworthy |
| `pkix` | Issuer-link and path validation over those stored bytes | Cross-sign reach is a path question. Hand-rolled chain walking in a pipeline would be a second, laxer validator — the thing `pkix`'s narrow RFC 5280 section 6 scope exists to prevent |
| `certledger` | The persistent store made **queryable**: SPKI-of-issuer / name / fingerprint keys, coverage state returned with every answer, and incremental inclusion verification. This is the certificate index, and it is the prerequisite for every analysis here | It is `cl.states`' phase-3 wiring and the deferred store under another name — one store serving incidents and the map, or the two will disagree in public. Gated, as always, on the fetch layer and the anchor decision |
| `ctspy` | Keep serving fleet artifacts (`inclusion_sweep()`) as the CT section's data | Already true; the renderer consumes it rather than re-deriving it |
| `namespy` | A DANE/TLSA lookup and DNSSEC anchor handling | TLSA exists in its codec (`namespy/enums.py:260`, RFC 6698 section 3) but there is no validation path. `certledger/ROADMAP.md` claimed `namespy` "does not exist yet" — corrected 2026-11-05: it is implemented, and the gap is DANE rather than the resolver |
| `keyproof` | The blocklist artifact | `trustatlas` renders it; authoring compromise claims, with their oracle problem, is `keyproof`'s |

### What the first join measured (2026-11-05)

The reader half of the `asn1core` row landed the same day — obligation `dk.pem`, commit `268cb10`: RFC 7468
armour in all three grammars of §3, encapsulation boundaries case-sensitive per erratum 4508, Appendix A vendored
verbatim as the negative corpus, 17 tests, plus 75 operating-system certificates round-tripped with zero
failures by `tools/crosscheck_pem.py`. That made an end-to-end run over two real sources possible with no
fixture anywhere in the path:

- **curl/certifi's `cacert.pem`** — 238,641 octets, **120 blocks**, every one labelled `CERTIFICATE`, every one
  conforming to Figure 3, and **120 of 120 byte-identical when re-encoded here**. A strict generator and the
  ecosystem's generator agree on real data, which is the cheapest possible confirmation that the strict path is
  not a private fantasy. None of the 120 is past its `notAfter`.
- **This machine's stores** (`LocalMachine\Root`, `LocalMachine\CA`, `CurrentUser\Root`) — 75 certificates,
  **74 distinct keys**.
- **The join — 29 keys in both**, 91 bundle-only, 45 store-only. An independent join by subject DN returns the
  same **29**, with zero certificates whose name matched while their key did not. Two different keys over the
  same pipeline agreeing is what makes that a measurement rather than a bug report.

The 45 store-only certificates are not "CAs Mozilla rejects", and that is the part P2 has to handle. Measured
from the certificates themselves: **10 are already past `notAfter`** (earliest end date 1999-12-30: the 1997
Microsoft and VeriSign roots, Thawte Timestamping CA, DST Root CA X3); **5 carry an EKU that omits TLS server
authentication**, four of them still inside their window — three `CN=AMD-KEYID-…` and
`CN=Electronic Arts, Inc., OU=EA SPEAR AntiCheat Engineering`, valid to 2027-2032; the rest are time-stamping,
Authenticode, TPM and hardware-compatibility roots. `CurrentUser\Root` additionally holds
`CN=Blizzard Battle.net Local Cert`, `CN=Root Agency`, and `CN=DESKTOP-CIJSDJG`, which runs to **3025-06-27**.
One caveat on the method: the bundle side carries **no EKU at all** (120 of 120), so EKU can *exclude* a store
certificate but can never *confirm* a bundle one.

Three consequences, all load-bearing:

1. **P2's diff must split by EKU and by store**, or its headline number is noise. Counting
   `CN=DESKTOP-CIJSDJG` beside `CN=DigiCert Global Root CA` measures nothing about trust.
2. **"Every globally trusted CA" is bundle-scoped with a named source, never machine-scoped.** A machine's
   trust root set is a TLS set plus a code-signing set plus expired residue plus whatever a launcher or an
   anti-cheat agent installed. The per-machine view is a separate artifact, and the interception roots are the
   first evidence it is worth having on its own terms.
3. **"Trusted" is defined per program, and CT obligation follows that same boundary** — so a bit is the wrong
   data type. MDN records that "Firefox desktop, starting from version 135, and Firefox for Android, starting
   from version 145, require CT log inclusion for all certificates issued by certificate authorities in
   Mozilla's Root CA Program", while Chrome's policy applies to certificates chaining to the roots *Chrome*
   ships and judges compliance by SCT count, log state and operator distinctness instead. Apple's requirement
   varies again. Nothing enforces the union of those sets, so an anchor view needs **program + snapshot date**
   on every row — "trusted in Mozilla's program as of 2026-11-06", never a bare `trusted: true`.
   See `certledger/BROWSER-POLICY.md` §1 for the quotations and §3 for the provenance pattern worth copying:
   Chrome's log list is **signed, versioned (`96.2`) and republished daily**, which is what an assertion that
   moves every day should look like.

## Phasing, each with an exit test

- **P0 — paper.** This document, the portfolio amendment, the naming decision recorded. *Exit:* PORTFOLIO
  sections 3, 5, 6, 7 and 9 agree with this file, and nothing in the directory is buildable.
- **P1 — probe and schema.** One script that probes every candidate source and records status, byte count and
  SHA-256 into a catalog artifact. *Exit:* the 404 rows are either gone or listed as explicitly unavailable, and a
  test re-reads the committed catalog and re-hashes the bytes it claims.
- **P2 — Windows and one bundle, end to end.** Local store export plus `cacert.pem` through `asn1core` into
  `anchor`/`store` artifacts with provenance; SPKI join between them (the join itself is demonstrated above —
  29 keys, corroborated by subject — so what is left is persisting it as artifacts and splitting by EKU and by
  store). *Exit:* the diff between this machine's
  store and the Mozilla-derived bundle is produced by a command, and a second run reproduces its counts.
- **P3 — derivation edges computed.** Subset relations between at least four bundles, from hashes alone. *Exit:*
  every edge carries `verified: true`, and at least one asserted-but-false edge is caught and kept as a test.
- **P4 — the index begins, with coverage attached.** One log fully walked into append-only segments and made
  queryable by issuer SPKI, name and fingerprint, with `GapState` returned as part of the answer. *Exit:* a query
  for a key that log never issued returns an empty set **that states its coverage**, and a test proves that
  injecting a gap changes the answer's grade while leaving its rows identical.
- **P5 — the renderer exists.** Vite/React static build over the artifacts. *Exit:* the build reads only
  committed JSON, and a fixture with a stale `retrieved_at` renders as stale.
- **P6 — blocklist overlay, then cross-sign reach.** Seeded with the eight compromised SPKI hashes. *Exit:*
  `AAA Certificate Services` is displayed as the path by which those keys reach stores that never listed eMudhra.
- **P7 — local audit shipped.** *Exit:* on this machine it reports the 68/0 measurement above with no network.

P4 is the expensive one and it is not sequenced by taste: it waits on the fetch layer, the anchor decision, and a
hosting budget, exactly as the walk always has. P1 to P3 answer real questions over a handful of sources with no
network cost at all, which is why they come first.

## Obligations

| Id | Obligation |
| --- | --- |
| `ta.probe` | Source catalog generated by probing, never hand-written, with per-source status |
| `ta.provenance` | Every artifact carries source, time, SHA-256, parser and the reproducing command |
| `ta.schema` | Anchor, store, edge and incident records joined on SPKI SHA-256 |
| `ta.derivation` | Edges computed from hash sets; an unverifiable edge is not drawn |
| `ta.local` | Local store read, Windows first, offline |
| `ta.gating` | No section may display behaviour whose supporting code does not exist |
| `ta.freshness` | Staleness surfaced, never hidden |
| `ta.reach` | Cross-sign reach computed via `pkix`, not by hand |
| `ta.index` | The certificate index, owned by `certledger`: SPKI / name / fingerprint keys, `GapState` returned with every answer, verification incremental rather than total |
| `ta.stability` | **Implemented 2026-11-05.** A source is fetched twice before it counts: identical SHA-256 across runs makes it an artifact, differing bytes make it a web page. Found the hard way — two of thirteen "available" sources were HTML listings that change every request, and the sweep now reports 11 stable |

## Decisions this needs from a human

1. **Redistribution posture.** Summarising stores — hashes, counts, names — is a different act from republishing
   bundles, and root-program material ships with program terms. `cl.aup-review` should cover this alongside the
   CT log-list question. Until it is reviewed, the default is hashes-and-counts.
2. **Hosting and cost, for both halves.** The site is a static build and cheap. **The index is not**: a full
   walk is ~27M requests for a single Google log at the measured 32-entries-per-request ceiling, with storage in
   the billions of records, so it needs a hosting and bandwidth decision *and* the anchor decision before it can
   start. If the answer is "no budget", the index stays scoped to the logs an analysis actually needs, and says
   so on every page.
3. **Name ratification** — **decided 2026-11-05: `trustatlas`.** `anchoratlas` stays the fallback that also
   passes the rule. Still open beneath it: the off-PyPI brand check, which has to happen before publication
   rather than after.

## Unverified — check before repeating any of this

- The six 404 rows. They are my wrong guesses, not evidence that the sources do not exist.
- Whether the ecosystem's stores really all descend from NSS. Very likely, and P3's job is to prove it store by
  store; nothing here states it as measured fact.
- Whether the eight compromised SPKI hashes reach every store by the same path. The AAA cross-sign is confirmed;
  per-store reach is what the tool has to compute.
- Non-Windows local stores. The macOS and Linux read paths were not exercised from this machine.
- Brand collisions off PyPI. `names.py` checks package indexes; it does not check whether the same name already
  exists on the web. Check before publishing anything.



