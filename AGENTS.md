# Instructions for coding agents

**Plan only. No code, no package, no `package.json`, no build file in this directory.** Scaffolding here would
be the failure mode this portfolio names: the risk is not implementation difficulty, it is a directory of
config files that implies a product exists.

## Read in this order

`PLAN.md` in full, then `PORTFOLIO.md` sections 5, 6, 7 and 9. Two sections of `PLAN.md` are load-bearing and
must not be summarised away: the **gating rule** (a section may display software behaviour only when the code
behind it exists — which is why BGP, RPKI and whois are *not* sections of this site, since those projects are
shells that raise `NotImplementedError`), and **Unverified**, which lists what is guessed rather than measured.

## What this directory must never become

- **Not the place where protocol logic gets written.** Parsing anchors is `asn1core`; path and issuer links are
  `pkix`; CT is `ctspy`; storage and coverage states are `certledger`; DANE and DNSSEC are `namespy`. When the
  pipeline needs something they do not do, the obligation goes into *that* project, and `PLAN.md`'s SDK table
  gains a row. Writing it in JavaScript here would create a second, laxer implementation of PKI — the one thing
  a trust map cannot survive.
- **Not a live-oracle.** The renderer reads committed artifacts. A page that fetches third-party data at view
  time cannot state what it saw when, and its absence claims become unanchored.
- **Not an author of compromise claims.** That is `keyproof/PLAN.md`, including its oracle problem. This site
  renders a blocklist; it never writes one.
- **Not a publisher of bundles by default.** Program materials carry terms; `cl.aup-review` has not ruled. Until
  it does, the posture is hashes-and-counts.

## Conventions that apply when it is finally built

Python 3.12+ for the pipeline (`from __future__ import annotations`, `collections.abc`, `X | None`); every
artifact carries the provenance fields in `PLAN.md`; `ruff format` decides line breaks; scratch output goes
outside the repository. The name has been measured free with zero one-keystroke neighbours, and off-PyPI brand
collisions have **not** been checked — do that before anything is published.
