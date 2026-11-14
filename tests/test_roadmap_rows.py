"""The obligation matrix and the test suite cannot drift apart silently (`ROADMAP.md` row `ta.roadmap_gate`).

`ROADMAP.md`'s honesty rule says a row may read `[ok]` only when a named test would fail if the behaviour
regressed. A rule in prose is checked by whoever remembers it; this file checks it on every run. Modelled on
ctspy's `tests/test_roadmap_rows.py`, adapted to this matrix's shape: rows here name scripts rather than
callables, so the evidence is the `Test: tests/<file>.py::<function>` id written in the Where cell.

Three directions are pinned, all read from the tree at test time rather than from a list kept here, because
the suite grows while the matrix is edited:

- a row claiming `[ok]` names a test id, and that id resolves to a function defined in an existing file;
- an id marked `(to be written)` does not resolve yet - once the test exists, the marker is a stale claim;
- an id not marked `(to be written)` does resolve, whatever else its parenthetical says.

Resolution is textual (`def <name>(` at any indentation), not an import and not a pytest collection, so a
test file under concurrent edit or with a failing import is still judged on what it defines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "ROADMAP.md"
BAR = chr(124)
TICK = chr(96)
DONE = "[ok]"
TO_BE_WRITTEN = "to be written"

# `Test: `tests/x.py::name`` optionally followed by one parenthetical, e.g. `(to be written)` or
# `(exists, fails; ...)`. Only the `Test:` prefix counts: a row that cites another project's test in passing
# (`ta.spki_key_identity` cites asn1core's) is not naming its own evidence.
TEST_ID = re.compile(
    r"Test:\s*"
    + TICK
    + r"(?P<file>[^"
    + TICK
    + r":]+)::(?P<test>[^"
    + TICK
    + r"]+)"
    + TICK
    + r"(?:\s*\((?P<note>[^)]*)\))?"
)


@dataclass(frozen=True)
class NamedTest:
    obligation: str
    file: str
    test: str
    note: str | None

    @property
    def function(self) -> str:
        """A parametrised id (`name[case]`) still names its function."""
        return self.test.split("[", 1)[0].strip()

    @property
    def to_be_written(self) -> bool:
        return self.note is not None and self.note.strip().startswith(TO_BE_WRITTEN)

    def __str__(self) -> str:
        return f"{self.obligation}: {self.file}::{self.test}"


@dataclass(frozen=True)
class Row:
    obligation: str
    status: str
    where: str

    def test_ids(self) -> list[NamedTest]:
        return [
            NamedTest(self.obligation, m["file"].strip(), m["test"].strip(), m["note"])
            for m in TEST_ID.finditer(self.where)
        ]


def roadmap_rows() -> list[Row]:
    """Every obligation row of every table, as `| `ta.x` | spec | status | where | milestone |`."""
    rows = []
    for line in ROADMAP.read_text(encoding="utf-8").splitlines():
        if not line.startswith(BAR + " " + TICK + "ta."):
            continue
        cells = [cell.strip() for cell in line.split(BAR)]
        if len(cells) < 7:
            continue
        # The Where cell is prose and may one day hold a bar of its own, so it is everything between the
        # status column and the milestone column rather than a single split cell.
        rows.append(Row(cells[1].strip(TICK), cells[3].strip(TICK), BAR.join(cells[4:-2])))
    return rows


def defines(test_id: NamedTest) -> bool:
    path = ROOT / test_id.file
    if not path.is_file():
        return False
    pattern = re.compile(
        r"^[ \t]*(?:async[ \t]+)?def[ \t]+" + re.escape(test_id.function) + r"[ \t]*\(", re.M
    )
    return pattern.search(path.read_text(encoding="utf-8")) is not None


def test_the_parser_finds_the_obligation_rows() -> None:
    """An empty parse would pass every other check here vacuously, so the parse itself is pinned."""
    rows = roadmap_rows()
    obligations = {row.obligation for row in rows}
    assert len(obligations) >= 30, f"ROADMAP.md parsed to {len(obligations)} obligation ids"
    assert len(obligations) == len(rows), "an obligation id appears on two rows"
    assert all(row.status.startswith("[") and row.status.endswith("]") for row in rows), [
        (row.obligation, row.status) for row in rows if not row.status.startswith("[")
    ]
    assert sum(len(row.test_ids()) for row in rows) >= 10, "the Test: ids stopped parsing"


def test_a_row_claimed_ok_names_a_test_that_exists() -> None:
    problems = []
    for row in roadmap_rows():
        if row.status != DONE:
            continue
        ids = row.test_ids()
        if not ids:
            problems.append(f"{row.obligation} reads {DONE} without naming a Test: id")
        for test_id in ids:
            if test_id.to_be_written:
                problems.append(f"{test_id} reads {DONE} but its test is (to be written)")
            elif not defines(test_id):
                problems.append(f"{test_id} reads {DONE} but no such function exists")
    assert not problems, "the matrix claims more than it can show: " + "; ".join(problems)


def test_a_test_marked_to_be_written_does_not_exist_yet() -> None:
    stale = [
        str(test_id)
        for row in roadmap_rows()
        for test_id in row.test_ids()
        if test_id.to_be_written and defines(test_id)
    ]
    assert not stale, "these tests exist; drop their (to be written) marker: " + "; ".join(stale)


def test_a_test_not_marked_to_be_written_exists() -> None:
    missing = [
        str(test_id)
        for row in roadmap_rows()
        for test_id in row.test_ids()
        if not test_id.to_be_written and not defines(test_id)
    ]
    assert not missing, (
        "these Test: ids name nothing; mark them (to be written) or write them: "
        + "; ".join(missing)
    )
