# Instructions for coding agents

**Fetchers only. No package, no `package.json`, no PyPI distribution, no protocol logic, no renderer.** This
directory graduated from plan-only on 2026-11-05, and narrowly: `tools/` may hold stdlib-only scripts that write
artifacts to the data directory. The web app is still unbuilt and `PLAN.md`'s gating rule still binds it. Do not
scaffold the thing you are about to design.

## Read in this order

`PLAN.md` in full, then `certledger/HARVEST-PLAN.md` (which owns the CT side of the pipeline), then
`PORTFOLIO.md` sections 5, 6, 7 and 9. Two sections of `PLAN.md` are load-bearing and must not be summarised
away: the **gating rule** (a section may display software behaviour only when the code behind it exists — which
is why BGP, RPKI and whois are *not* sections of this site, since those projects are shells that raise
`NotImplementedError`), and **Unverified**, which lists what is guessed rather than measured.

## What this directory must never become

- **Not the place where protocol logic gets written.** Parsing anchors is `asn1core`; path and issuer links are
  `pkix`; CT is `ctspy`; storage and coverage states are `certledger`; DANE and DNSSEC are `namespy`. When the
  pipeline needs something they do not do, the obligation goes into *that* project, and `PLAN.md`'s SDK table
  gains a row. Writing it in Python here would create a second, laxer implementation of PKI — the one thing a
  trust map cannot survive. `tools/probe_sources.py` is the pattern: it records where bytes came from and
  declines to interpret them.
- **Not a live-oracle.** The renderer reads committed artifacts. A page that fetches third-party data at view
  time cannot state what it saw when, and its absence claims become unanchored.
- **Not an author of compromise claims.** That is `keyproof/PLAN.md`, including its oracle problem. This site
  renders a blocklist; it never writes one.
- **Not a publisher of bundles by default.** Program materials carry terms; `cl.aup-review` has not ruled. Until
  it does, the posture is hashes-and-counts.

## Data directory

Artifacts go to the directory named by `--data` (container default `/data`, host `M:\trustatlas`), never into
this repository. Its rules are in its own `README.md`; the one that bites is that a partial run must not move
`sources/catalog.json`, which is what a `--only` sweep is for.

## Conventions

Python 3.12+ for the pipeline (`from __future__ import annotations`, `collections.abc`, `X | None`); every
artifact carries the provenance fields in `PLAN.md`; `ruff format` decides line breaks; scratch output goes
outside the repository. The name has been measured free with zero one-keystroke neighbours, and off-PyPI brand
collisions have **not** been checked — do that before anything is published.


## Finding work

If the person gave you a task, do that task. If you arrived with nothing to do, run this from `D:\code`:

    python -m projecthub pickup --who <your name>

Its output is your assignment. `NO WORK` is a real answer: ask the person what to work on.

## Commands

Run from inside this directory, with `PYTHONDONTWRITEBYTECODE=1`; never a formatter from `D:\code`.

    python -m pytest -q
    python -m ruff check tools tests
    python -m ruff format --check tools tests
    python -m mypy

The suite has 39 tests and, at the time of writing, 7 of them fail (`ROADMAP.md` row `ta.suite_green` says why and
which side is wrong in each). A red test beside a `[part]` row is a fact to fix, never one to skip.

## Dependencies

Standard library only in `tools/`; `dependencies = []` in `pyproject.toml` is pinned by `tests/test_pyproject.py`.
The `cryptography` package is *permitted* by the workspace rule for cryptographic primitives, and is still not used
here, because nothing in this directory performs one: certificates are read by `asn1core`, called as a subprocess by
path (`tools/check_spki_artifact.py`), not imported. If a script needs `asn1core`, call it the same way.
