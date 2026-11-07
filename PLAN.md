# trustatlas: the supply chain of trust anchors

Status: **P1 landed 2026-11-05; P2's first collector landed 2026-11-06.** `tools/probe_sources.py` generates the
source catalog, `tools/collect_store.py` collects a live program store, `Dockerfile` + `compose.yaml` run them, and
artifacts live in `M:\trustatlas`, the `--data` directory: the source catalog is `sources/catalog.json` under it
(`/data/sources/catalog.json` in the container), never a file in this repository. Still unbuilt: the remaining readers (P2), the derivation edges (P3), the index
(P4, owned by `certledger`), and the renderer. `AGENTS.md` governs what may be added here. No `package.json`, no
PyPI, no protocol logic.

## What `collect_store.py` measured, on 2026-11-06, on this machine

The plan called the local store audit "the most useful tool in this plan and the cheapest". It is now that tool, and
the answers are artifacts (`M:\trustatlas\store\windows.machine.json`, `--with-der` also writes 68 hash-addressed
DER files):

- **`Cert:\LocalMachine\Root` holds 68 anchors; `AuthRoot` holds 52; `Disallowed` holds 0.** The 68 reproduces the
  hand measurement in this file independently, and all 52 `AuthRoot` certificates are also in `Root`.
- **`AAA Certificate Services` is not in either store** — while `COMODO RSA Certification Authority` *is*. So the
  Comodo key the eMudhra guidance asks users to disable is absent here in the specific form the guidance names, and
  the neighbouring Comodo root that the same sentence could easily be conflated with is present. That distinction is
  the artifact's whole value: a browser-error-page inference cannot draw it, and `Disallowed` being empty shows the
  machine reached this state by never having the certificate rather than by blocking it.
- Control, so the absence is not the tool's: `--grep Microsoft` finds **16** anchors in the same run's data.
- **No anchor reports an EKU extension.** Root certificates commonly carry none, and the artifact records absence
  without deciding what absence means — that is RFC 5280's to say. What the tool will not do is silently upgrade it
  to "trusted for TLS server authentication"; `with_server_auth_eku` is 0 and stays 0.
- `ConvertTo-Json` defaults to `-Depth 2`, which serialises a nested array as `System.Object[]`. Left alone, every
  EKU list would have come back as that string and the honest reading would have been "no anchor has an EKU" — a
  serializer artifact dressed as a fact about the store. `-Depth 6` is now explicit.

## The Microsoft program, reached from the container, and deliberately not counted

The membership API I expected at `learn.microsoft.com/api/membership/rootcert` **404s**, as does
`microsoft.com/pkiops/certs/RootCerts.json` — both were recollections, and probing cost one command each.
What actually exists is Microsoft's published CTL, and it is reachable from a Linux container:

```
authrootstl.cab          80,353 octets  application/vnd.ms-cab-compressed  sha256 c0aa761f…  STABLE
disallowedcertstl.cab     5,652 octets  application/vnd.ms-cab-compressed  sha256 1f2719b1…  STABLE
```

Both over **plain HTTP** — `https://` on that host fails — and stable across two fetches, which is
`probe_sources.py`'s own verdict (`80353 B, 0 PEM, stable` via `--only`, so no partial sweep moved
`catalog.json`). `collect_ctl.py` fetches, checks the `MSCF` magic, and hashes. It reports
`certificates_enumerated: 0` and `decoded: false`, because enumerating CTL entries means unpacking a CAB
and walking signed trust blobs in a Microsoft binary format, and that is `pkix`'s work. A membership count
written here would be a guess with a JSON wrapper.

The pin is not a placeholder for the real answer. These URLs carry **no transport security**, so the only
integrity protection is the signature *inside* the CAB — precisely the check `pkix` has to implement, and
until it does, "bytes as delivered over HTTP on 2026-11-07, SHA-256 c0aa761f…" is the strongest honest
statement available about the Windows program. A later decoder can at least prove which bytes it was fed.
The container re-fetched with `--refresh` and reproduced both hashes, so the pin survives the environment
change.

`disallowedcertstl.cab` is the blocklist, and it is the artifact the site is meant to *render* — the
eMudhra-era guidance asks users to disable a root, and a pinned, dated Microsoft blocklist answers whether
the program moved, independently of any machine's store. Rendering it is not the same as authoring one:
`keyproof` owns compromise claims, and nothing here makes one.

Obligation now **filed**, not just noted: `pkix/ROADMAP.md` gained milestone **M7** and three `[ ]`
rows — `cab.member()`, `ctl.root_program()`, `ctl.signed_by_microsoft()` — backed by `pkix/cab.py` and
`pkix/ctl.py` stubs that raise rather than return empty lists, because "the Windows program trusts
nothing" and "this build cannot read the CTL" are different claims and only one is true. `pkix`'s own
gate (`tests/test_roadmap_rows.py::test_every_row_names_a_real_callable`) failed the moment the rows
existed without the callables — a matrix row that names nothing is a wish, and the project enforces
that rather than trusting the document. With M7 landed, the Microsoft program becomes a first class
joinable set next to NSS, curl and certifi, and the laptop-only `collect_store.py` stops being the only
way to say anything about Windows trust at all.



## Where each collector runs, because the target is a Linux container

`Dockerfile` is `python:3.12-slim` and AWS Fargate runs Linux containers only, so a tool that shells out to
`powershell.exe` and reads `Cert:\LocalMachine` can never run in the image. That was a placement error, not a
portability nit, and it is now explicit. Two classes, deliberately not mixed:

- **Container-resident, Fargate-able: program-published lists.** `collect_certdata.py` (Mozilla, HTTPS),
  `collect_bundle.py --url` (curl, HTTPS), `join_programs.py`. `compose.yaml` has a `collect` service that runs
  all three; it was executed with Docker 29.3.1 and is not a claim about a pipeline nobody ran.
- **Host-resident, one machine at a time: realized stores.** `collect_store.py` reads the Windows certificate
  store and now **refuses on non-Windows with exit 3**, naming why: one machine's store only exists on that
  machine. Its Linux equivalent is the `ca-certificates` bundle plus its hash; its macOS equivalent is
  `security trust-settings-export` (`PLAN.md` said so before this tool forgot).

`--data` defaults to `/data` in all four tools, matching `probe_sources.py` and the `${TRUSTATLAS_DATA:-M:/trustatlas}:/data`
bind; the `M:\trustatlas` default I had written would have created a directory literally named `M:\trustatlas`
inside the container. The image has no `certifi` package and will not gain one, so the bundle collector takes
`--url` instead.

**What the container run measured**, and it improved the finding:

```
NSS built-ins: 169 certificates, 117 stated trusted for server authentication (1,356,175 octets)
curl:          118 PEM blocks, 118 distinct certificates
NSS 169 x curl 118: shared 118, only-curl 0 -> curl is a subset of Mozilla/NSS built-ins
```

So design goal 4 is met for the first time: **`cacert.pem ⊂ NSS built-ins` is now a hash check that passes**, and
the "51-root gap" recorded earlier is explained rather than asserted — those 51 are NSS anchors curl does not
ship (client-auth, email-only, and root-certificate-version variants such as `COMODO Certification Authority` and
`Starfield Class 2 CA` sitting beside their newer `RSA`/`G2` siblings).

Set against the host run's certifi result, the two bundles that are habitually called interchangeable are not:
**curl carries 118 certificates, all inside NSS; certifi carries 120, five of which are in no NSS built-in at all.**
Whatever else the five eMudhra-adjacent names mean, the asymmetry is between curl and certifi, not between
either and "Mozilla's bundle".

Two bugs the container found that the host had hidden: `collect_certdata` created `raw/` but never `store/`,
which worked on the host only because the directory already existed; and `--url` was referenced before it was
declared, because a patch anchored on text `ruff format` had already rewrapped. Both are the same lesson as the
soft-404 earlier: an environment you already trust stops testing you.



## The two bundles that are called the same thing are ten certificates apart

Both sides now carry names from their own files, so the difference is not a count but a list.
**certifi (120) × curl (118): 114 shared, 6 only in certifi, 4 only in curl — neither a subset.**

| Only in certifi (6) | Only in curl (4) |
| --- | --- |
| `emSign Root CA - C1` | `Telia RSA TLS Root CA v3` |
| `emSign ECC Root CA - G3` | `Telia EC TLS Root CA v3` |
| `emSign ECC Root CA - C3` | `SECOM TLS RSA Root CA 2024` |
| `SecureSign Root CA12` | `SECOM TLS ECC Root CA 2024` |
| `ePKI Root Certification Authority` | |
| `Atos TrustedRoot 2011` | |

The asymmetry has a shape worth stating precisely, because it is the useful kind:

- **curl is quicker to add.** All four curl-only entries are 2024-generation roots (Telia v3, SECOM 2024).
  A runtime pinned to certifi is missing four roots that curl already ships.
- **certifi keeps and carries more.** Five of its six extras — the three `emSign`/eMudhra roots,
  `SecureSign Root CA12`, `ePKI` — are in **no NSS built-in**, which is why curl (a strict subset of NSS,
  118 of 118) does not have them. The sixth, `Atos TrustedRoot 2011`, *is* in NSS: curl dropped it,
  certifi did not.
- So the two failure modes are different. One bundle lags on additions; the other ships roots the program
  it is said to mirror no longer carries. Neither is visible from either bundle's documentation, and both
  were invisible until someone hashed the two against the program.

**A verification asymmetry between the sources, recorded so it is not mistaken for equal rigour:**
certifi states a SHA-256 of DER per block and 120 of 120 match what `collect_bundle.py` hashed, so its
join key is externally confirmed. curl states names but **no fingerprints — 0 of 118 checked**. Its hashes
are therefore produced by the same code and validated by nothing but itself. Same pipeline, different
evidence, and the artifact says which is which (`fingerprint_checked`).



## Third program, and the derivation edge gets tested

`collect_certdata.py` reads Mozilla's `certdata.txt` at its source — `CKA_LABEL`, `CKA_VALUE` as
`MULTILINE_OCTAL`, `CKA_TRUST_*` — and lands **169 certificates, 1,356,175 octets, 117 stated
trusted for server authentication**. The 169 and the octet count both reproduce figures `PLAN.md`
already held from an unrelated measurement, so the reader is corroborated before it is trusted.

Two failures worth keeping in the file. The GitHub mirror `raw.githubusercontent.com/nss-dev/nss/MAIN/...`,
recorded as the working URL two days ago, **now 404s**; `hg.mozilla.org/mozilla-central/raw-file/tip/...`
serves the same 1,356,175 bytes. Stability is not durability — fetching the same bytes twice yesterday
says nothing about whether the URL exists today — so the tool now walks a candidate list and writes the
ruled-out attempts beside the artifact. And my first trust count returned 0 because I compared against
`CKT_NSS_TRUSTED_CONNECT_PEER`, **a constant I invented**; the value in the dump is `TRUSTED_DELEGATOR`.
A clean, quiet zero was my error wearing the store's clothes.

`collect_bundle.py` now also reads the comment header above each PEM block. That turned into something
better than names: certifi states a **SHA-256 of DER per certificate**, and **120 of 120 match what this
script hashed**. The collector's join key is therefore validated by the bundle maintainer's own data,
which no fixture-based test of mine could establish. All 120 also carry names, from lines in the file.

**The derivation edge, checked rather than asserted:**

| Join | Shared | Only in first | Only in second | Verdict |
| --- | --- | --- | --- | --- |
| NSS 169 × certifi 120 | 115 | 54 | 5 | neither is a subset |
| NSS 169 × Windows 68 | 38 | 131 | 30 | neither is a subset |
| Windows 68 × certifi 120 | 29 | 39 | 91 | neither is a subset |

"certifi is Mozilla's bundle" is the common shorthand, and as a hash check it is false in both
directions: 54 roots Mozilla ships are not in certifi (expected — email-only and client-auth anchors),
and **5 certificates certifi ships are in no NSS built-in at all**. Named from certifi's own headers,
those five are `emSign Root CA - C1`, `emSign ECC Root CA - G3`, `emSign ECC Root CA - C3`,
`SecureSign Root CA12` and `ePKI Root Certification Authority`.

Three are **eMudhra** roots — the brand the October 2026 incident in this plan's opening is about. What
this artifact establishes is narrow and checkable: those certificates are in certifi's bundle and not in
Mozilla's, named by the labels each file carries, as of the timestamps in each artifact. Whether any key
is compromised is `keyproof`'s claim to make and this tool makes none of it; what the map adds is that a
program that ships "Mozilla's bundle" is shipping three roots Mozilla does not, and nobody reading the
documentation would know to ask.

Caveat the join states about itself: the key is certificate SHA-256, so a root and a cross-signed copy of
the same key are two entries. Any of the five could be a different certificate holding a key NSS also
holds. Only SPKI SHA-256 — `asn1core`, design goal 3 — can tell those two stories apart, and this is the
finding that makes that dependency load-bearing rather than tidy.



## Cross-program join, the same day

`collect_bundle.py` reads a PEM bundle program the same way — split blocks, base64-decode, SHA-256 the DER, name
nothing — and `join_programs.py` joins two artifacts on certificate SHA-256 and prints both one-sided remainders.
certifi's local bundle carries **120 distinct certificates** today (the 118 recorded above was an earlier version of
the package, and the count is a property of the file, so it is reported per run with the file's own SHA-256).

**Windows machine store (68) × certifi (120): 29 shared, 39 only in Windows, 91 only in certifi.** Two things come
out of the 39, and they are the reason the join exists:

- **Roots that other programs dropped are still trusted here**: `DST Root CA X3` and `Starfield Class 2
  Certification Authority` are in the machine store and in no certifi certificate.
- **Non-web anchors sit in the same store as web roots**: `Electronic Arts, Inc. / EA SPEAR AntiCheat Engineering`,
  `Blizzard Battle.net Local Cert`, `DigiCert CS ECC P384 Root G5` and `Microsoft ECC TS Root Certificate Authority
  2018` all appear in `Cert:\LocalMachine\Root` and nowhere in certifi. This is design goal 6's claim — a machine
  store is not one trust set — evidenced rather than asserted: code-signing, timestamping and two locally installed
  application CAs are trusted by the same mechanism as TLS roots, and no browser-facing inference would separate them.

These are statements about what the store contains, not about whether any of it is compromised; `keyproof/PLAN.md`
owns compromise claims and nothing here makes one. The asymmetry is also a fact: the bundle side is hashes only, so
its 91 can be counted but not named. Naming them means parsing, and parsing is `asn1core`'s.

Scope, honestly bounded: the OS is the parser here. Subject, validity and EKU are what Windows states; this script
decodes no certificate. The join key is therefore the **certificate** SHA-256, which cannot connect a root to a
cross-signed copy of the same key — and joining cross-signs is the point of the map. **SPKI SHA-256 is `asn1core`'s
obligation** (design goal 3), so the SDK table gains that row rather than this directory growing a second, laxer
PKI parser. The user-scope stores (`Cert:\CurrentUser\Root`) and other programs (NSS `certdata.txt`, CCADB CSV,
curl/certifi bundles) are the same shape of collector and are not yet written.

### Key level, measured 2026-11-07

The caveat above is a measurement now, because `asn1core` ships `spki_sha256` (`x509.py`, pinned by
`tests/test_x509_corpus.py::test_the_extracted_digests_match_an_independent_implementation`, which compares against
digests `cryptography` printed for the same bytes). Both sources were re-verified before anything was
concluded: certifi's installed `cacert.pem` reproduced **120/120** recorded digests and
`https://curl.se/ca/cacert.pem` reproduced **118/118**, so the bytes analysed are the bytes collected.

- **certifi (120) × curl (118): 114 shared certificates and 114 shared keys.** Neither bundle holds two
  certificates for one key. Of the 6 certifi-only and 4 curl-only certificates, **none** shares a key with
  the other program. The bundle-to-bundle gap is a difference in keys, not an artifact of cross-signing: for
  this pair the certificate-level join was hiding nothing.
- **A realized store does collapse: the Windows machine store's 68 distinct certificates carry 67 distinct
  keys.** One key (`871a9194f4eed5b3…`) is held by two certificates, both `CN=GTS Root R1, O=Google Trust
  Services LLC, C=US`, and both appear in `Root` and `AuthRoot`. `asn1core` decoded all 68 without a failure,
  alongside its own `tools/crosscheck_store.py` over 75 real certificates.

So the key-level join is not needed to explain bundle drift, and it is needed the moment a store enters the
join, because stores are where cross-signs live. Unchanged: the artifacts carry hashes and counts only, so
none of this is reproducible from them — the bytes were re-derived from recorded provenance in scratch, not
stored. Keeping DER is `cl.aup-review`'s question, not this tool's.


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

**How far that sentence reaches was measured on 2026-11-07, and it reaches less far than it reads.**
Derivation is a historical claim; membership is a present one, and the two come apart.
`tools/collect_java.py` reads this machine's JDK 26.0.1 `cacerts` through Java's own `keytool` and hashes what
it prints: **109 anchors**. Joined on certificate SHA-256 against the recorded `Mozilla/NSS built-ins`
artifact, the overlap is **59 of 117** when NSS is filtered to the anchors it trusts to delegate for TLS
(`join_programs.py --a-trust SERVER_AUTH`), and 76 of its 169 when it is not; the 17-anchor difference is
anchors Java ships that NSS keeps solely for S/MIME or code signing. Java holds **50 anchors that NSS does not
trust for TLS at all** — `verisignuniversalrootca`, `geotrustprimaryca`, `geotrustprimarycag2`,
`thawteprimaryrootcag3`, `entrustrootcag2`, `starfieldclass2ca` and 44 more, all recorded in
`java-x-nss.server-auth.json`. Neither store is a subset of the other, and the same verdict comes back against
certifi, against curl, and against this machine's Windows root store.

So inheritance stands as a claim about *origin* — these stores were assembled from Mozilla's list, and NSS
decisions move them — and must never be read as *congruence*. That gap is not a footnote to the map: four
stores on one machine, joined in an afternoon, disagree by fifty anchors. It is the map.

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

The obligation ids are the ones in `ROADMAP.md`; that file is the matrix and the only id set. This table
used to carry a second, shorter set (`ta.probe`, `ta.schema`, ...) that matched nothing on the board. Each
design goal below names the `ROADMAP.md` rows that carry it, with the retired id kept in brackets so an old
reference can still be followed.

| Design goal | `ROADMAP.md` rows |
| --- | --- |
| Source catalog generated by probing, never hand-written, with per-source status [was `ta.probe`] | `ta.probe_sources` |
| Every artifact carries source, time, SHA-256, parser and the reproducing command [was `ta.provenance`] | `ta.provenance_fields` |
| Anchor, store, edge and incident records joined on SPKI SHA-256 [was `ta.schema`] | `ta.join_programs`, `ta.spki_key_identity` |
| Edges computed from hash sets; an unverifiable edge is not drawn [was `ta.derivation`] | `ta.derive_issuer_edges` |
| Local store read, Windows first, offline [was `ta.local`] | `ta.collect_store` |
| No section may display behaviour whose supporting code does not exist [was `ta.gating`] | `ta.renderer` |
| Staleness surfaced, never hidden [was `ta.freshness`] | `ta.renderer` (the P5 exit test: a stale `retrieved_at` renders as stale) |
| Cross-sign reach computed via `pkix`, not by hand [was `ta.reach`] | none yet: P6 names it and no `ROADMAP.md` row carries it (recorded as an open question there) |
| The certificate index, owned by `certledger`: SPKI / name / fingerprint keys, `GapState` returned with every answer, verification incremental rather than total [was `ta.index`] | `ta.coverage_index` |
| A source is fetched twice before it counts [was `ta.stability`]. **Implemented 2026-11-05.** Identical SHA-256 across runs makes it an artifact, differing bytes make it a web page. Found the hard way — two of thirteen "available" sources were HTML listings that change every request, and the sweep now reports 11 stable | `ta.probe_sources` |

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



