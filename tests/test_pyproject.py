"""The configuration this project's `pyproject.toml` states is itself a claim, so it gets pinned here.

`pyproject.toml` says this directory ships no package and no runtime dependency. Both are refusals, and a
refusal nobody re-checks is a default that quietly changes: one added `dependencies` entry or one
`[build-system]` table turns the fetchers into a distribution, which `ROADMAP.md` §4 marks `[no]`. These
tests fail on that edit rather than leaving it to a reader of prose.

It also gives item 2 onward somewhere to land: `testpaths` needs the directory to exist, or pytest warns and
falls back to searching the whole tree from the current directory.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_fetchers_carry_no_runtime_dependency() -> None:
    assert CONFIG["project"]["dependencies"] == []


def test_there_is_no_build_backend_so_nothing_here_can_be_installed() -> None:
    assert "build-system" not in CONFIG


def test_the_dev_toolchain_is_pinned_to_projecthub_s_versions() -> None:
    dev = dict(item.split("==", 1) for item in CONFIG["project"]["optional-dependencies"]["dev"])
    assert dev == {
        "ruff": "0.15.12",
        "mypy": "1.20.2",
        "pytest": "9.0.3",
        "coverage": "7.17.0",
    }


def test_scripts_are_imported_from_tools_and_not_from_a_package() -> None:
    options = CONFIG["tool"]["pytest"]["ini_options"]
    assert options["testpaths"] == ["tests"]
    assert options["pythonpath"] == ["tools"]


def test_the_coverage_floor_is_eighty_five() -> None:
    assert CONFIG["tool"]["coverage"]["report"]["fail_under"] == 85
