"""The configuration this project's `pyproject.toml` states is itself a claim, so it gets pinned here.

`pyproject.toml` says the library (`src/trustatlas`, row `ta.package`) ships with no runtime dependency and that
the wheel carries only that library, never the collector scripts in `tools/`. Both are refusals as much as
settings: one added `dependencies` entry is the first step toward a second, laxer PKI, and a wheel that swept up
`tools/` would install fetchers that write to a data directory. These tests fail on that edit rather than
leaving it to a reader of prose. Until 2026-11-15 they pinned that nothing here was installable at all; the
owner's decision for an importable library changed that, in the same commit that built it.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_fetchers_carry_no_runtime_dependency() -> None:
    assert CONFIG["project"]["dependencies"] == []


def test_the_wheel_carries_the_library_and_never_the_collector_scripts() -> None:
    assert CONFIG["build-system"]["build-backend"] == "hatchling.build"
    assert CONFIG["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/trustatlas"]


def test_the_dev_toolchain_is_pinned_to_projecthub_s_versions() -> None:
    dev = dict(item.split("==", 1) for item in CONFIG["project"]["optional-dependencies"]["dev"])
    assert dev == {
        "ruff": "0.15.12",
        "mypy": "1.20.2",
        "pytest": "9.0.3",
        "coverage": "7.17.0",
    }


def test_scripts_and_library_are_imported_from_tools_and_src_never_the_root() -> None:
    options = CONFIG["tool"]["pytest"]["ini_options"]
    assert options["testpaths"] == ["tests"]
    assert options["pythonpath"] == ["tools", "src"]


def test_the_coverage_floor_is_eighty_five() -> None:
    assert CONFIG["tool"]["coverage"]["report"]["fail_under"] == 85
