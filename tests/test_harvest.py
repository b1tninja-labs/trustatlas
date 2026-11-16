"""The harvest page reads JSON artifacts and file names. It does not serve shard, tile, or certificate bytes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from explore import explore_data, route

from trustatlas import Atlas
from trustatlas.harvest import Harvest, HarvestError

NOW = datetime(2026, 11, 16, tzinfo=UTC)
SPKI = "ab" * 32
CERT = "cd" * 32
ISSUER = "12" * 32
SECRETS = (
    b"SECRET-SHARD-BYTES",
    b"SECRET-TILE-BYTES",
    b"SECRET-DER-BYTES",
    b"SECRET-PEM-BYTES",
    b"SECRET-RAW-BYTES",
    b"SECRET-SIG-BYTES",
    b"SECRET-CHECKPOINT",
    b"SECRET-DER-B64",
)


def write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def harvest_tree(tmp_path: Path) -> Path:
    write(
        tmp_path / "entries" / "demo" / "cursor.json",
        json.dumps(
            {
                "schema": "certledger.preserve-cursor/1",
                "description": "<script>alert(1)</script>",
                "origin": "https://tiger.example.test",
                "state": "rejected",
                "entries_written": 10,
                "updated_utc": "2026-11-16T21:00:25Z",
                "head": {"tree_size": 100, "signature_verified": True},
            }
        ).encode(),
    )
    write(tmp_path / "entries" / "demo" / "shard-000000.cle1", b"SECRET-SHARD-BYTES")
    write(
        tmp_path / "entries" / "tiled" / "cursor.json",
        json.dumps(
            {
                "schema": "certledger.preserve-tiles-cursor/1",
                "description": "Example tiled",
                "submission_url": "https://tiles.example.test",
                "state": "none",
                "tiles_written": 2,
                "entries_estimate": 512,
                "updated_utc": "2026-11-16T21:00:58Z",
                "note": "tiles were not re-proved into the root",
                "checkpoint": {"tree_size": 9000, "checkpoint_verified": True},
            }
        ).encode(),
    )
    write(tmp_path / "entries" / "tiled" / "checkpoint", b"SECRET-CHECKPOINT")
    write(tmp_path / "entries" / "tiled" / "tiles" / "tile-data-00000000.bin", b"SECRET-TILE-BYTES")
    write(
        tmp_path / "entries" / "tiled" / "tiles" / "tile-data-00000001.bin", b"SECRET-TILE-BYTES-2"
    )
    write(tmp_path / "entries" / "tiled" / "issuers" / f"{ISSUER}.der", b"SECRET-DER-BYTES")
    write(tmp_path / "entries" / "torn" / "cursor.json", b"{")
    write(
        tmp_path / "heads" / "demo" / "100.json",
        json.dumps(
            {
                "schema": "certledger.heads-journal/1",
                "tree_size": 100,
                "signature_verified": True,
                "state": "rejected",
                "root_hash_hex": "ab" * 32,
            }
        ).encode(),
    )
    write(tmp_path / "heads" / "demo" / "100.raw", b"SECRET-RAW-BYTES")
    write(
        tmp_path / "leaf-shards" / "demo" / "key-census.json",
        json.dumps(
            {
                "schema": "certledger.key-census/1",
                "distinct_keys": 3,
                "entries_read": 3,
                "limits": ["no weak-key verdict is stored"],
            }
        ).encode(),
    )
    write(tmp_path / "leaf-shards" / "demo" / "unscreenable.pem", b"SECRET-PEM-BYTES")
    write(tmp_path / "leaf-shards" / "demo" / "census-state.json", b"SECRET-CENSUS-STATE")
    write(
        tmp_path / "artifacts" / "ca-catalog-1-demo.json",
        json.dumps(
            {
                "schema": "certledger.ca-catalog/1",
                "written_utc": "2026-11-16T19:49:59Z",
                "entries_read": 1,
                "limits": ["a chain-asserted edge proves nothing"],
                "logs": [{"log_id": "ee" * 32, "url": "https://tiger.example.test"}],
                "cas": [
                    {
                        "spki_sha256": SPKI,
                        "sha256": CERT,
                        "ca": True,
                        "psc": False,
                        "der_bytes": 10,
                        "der_b64": "SECRET-DER-B64",
                        "sightings": [{"index": 4, "log_id": "ee" * 32, "where": "chain"}],
                        "issuers": [
                            {
                                "kind": "chain-asserted",
                                "spki_sha256": ISSUER,
                                "showings": [{"index": 4, "log_id": "ee" * 32}],
                            }
                        ],
                    }
                ],
            }
        ).encode(),
    )
    write(
        tmp_path / "coverage" / "coverage-index-from-preserve.json",
        json.dumps(
            {
                "schema": "certledger.coverage-index/1",
                "limits": ["an unwalked range is unread, not empty"],
                "logs": [
                    {
                        "origin": "https://tiger.example.test",
                        "state": "partial",
                        "complete": False,
                        "may_claim_absent": False,
                        "conflicted": False,
                        "log_id": "ee" * 32,
                        "head": {
                            "tree_size": 100,
                            "root_hash": "ab" * 32,
                            "trust_class": "unauthenticated",
                        },
                        "held": [[0, 10]],
                        "unwalked": [
                            {
                                "start": 10,
                                "end": 100,
                                "reason": "budget",
                                "detail": "UNWALKED-MARKER unread, not empty",
                            }
                        ],
                    }
                ],
            }
        ).encode(),
    )
    write(
        tmp_path / "journal" / "20261116" / "manifest.json",
        json.dumps(
            {"fetched_at": "2026-11-16T16:22:38+00:00", "documents": {"log_list.json": {"logs": 1}}}
        ).encode(),
    )
    write(tmp_path / "journal" / "20261116" / "log_list.sig", b"SECRET-SIG-BYTES")
    return tmp_path


def pages(tmp_path: Path) -> list[bytes]:
    atlas = Atlas(harvest_tree(tmp_path))
    paths = [
        "/",
        "/harvest",
        "/logs",
        "/logs/demo",
        "/logs/demo/shards",
        "/logs/tiled",
        "/logs/tiled/tiles",
        "/logs/tiled/tiles?limit=1&offset=1",
        "/logs/tiled/issuers",
        "/heads",
        "/heads/demo",
        "/census",
        "/census/demo",
        "/catalogs",
        f"/catalogs/ca-catalog-1-demo.json?q={SPKI[:8]}",
        "/coverage",
        "/journal",
        "/journal/20261116",
        "/stores",
    ]
    rendered = []
    for path in paths:
        status, body = route(atlas, path.split("?", 1)[0], _query(path), NOW)
        assert status == 200, path
        rendered.append(body)
    return rendered


def _query(path: str) -> dict[str, list[str]]:
    if "?" not in path:
        return {}
    from urllib.parse import parse_qs

    return parse_qs(path.split("?", 1)[1], keep_blank_values=True)


def test_pages_show_artifacts_and_not_their_bytes(tmp_path: Path) -> None:
    rendered = pages(tmp_path)
    joined = b"\n".join(rendered).decode()
    for secret in SECRETS:
        assert secret.decode() not in joined
    assert "SECRET-CENSUS-STATE" not in joined
    assert "certledger.preserve-cursor/1" in joined
    assert "certledger.preserve-tiles-cursor/1" in joined
    assert "certledger.key-census/1" in joined
    assert "certledger.ca-catalog/1" in joined
    assert "certledger.coverage-index/1" in joined
    assert "UNWALKED-MARKER unread, not empty" in joined
    assert "may_claim_absent False" in joined
    assert "chain-asserted" in joined
    assert SPKI in joined
    assert f"{ISSUER}.der" in joined
    assert "tile-data-00000001.bin" in joined
    assert "shard-000000.cle1" in joined
    assert "100.raw" in joined
    assert "not opened" in joined
    assert "bytes not shown" in joined
    assert "&lt;script&gt;" in joined
    assert "<script>alert" not in joined
    assert "<h1>Stores</h1>" in joined


def test_a_catalog_summary_drops_certificate_bytes(tmp_path: Path) -> None:
    summary = Harvest(harvest_tree(tmp_path)).catalog("ca-catalog-1-demo.json")
    assert "SECRET-DER-B64" not in repr(summary)
    assert summary.ca_count == 1
    assert summary.edge_kinds == (("chain-asserted", 1),)
    assert summary.rows[0].sightings == 1
    assert summary.rows[0].issuers[0].showings == 1


def test_file_sizes_come_from_stat(tmp_path: Path) -> None:
    harvest = Harvest(harvest_tree(tmp_path))
    tiles = harvest.tiles("tiled")
    assert [item.name for item in tiles] == ["tile-data-00000000.bin", "tile-data-00000001.bin"]
    assert tiles[0].size == len(b"SECRET-TILE-BYTES")
    assert harvest.checkpoint_size("tiled") == len(b"SECRET-CHECKPOINT")


def test_a_torn_cursor_is_reported(tmp_path: Path) -> None:
    _doc, error = Harvest(harvest_tree(tmp_path)).cursor("torn")
    assert error == "not valid JSON"


def test_a_path_that_escapes_the_tree_is_refused(tmp_path: Path) -> None:
    atlas = Atlas(harvest_tree(tmp_path))
    for path in (
        "/logs/../coverage",
        "/logs/%2e%2e",
        "/catalogs/..%2F.env",
        "/heads/demo/100.json",
    ):
        status, body = route(atlas, path, {}, NOW)
        assert status == 404, path
        assert b"SECRET" not in body
    with pytest.raises(HarvestError):
        Harvest(tmp_path).tiles("../tiled")


def test_an_empty_directory_stays_on_the_store_inventory(tmp_path: Path) -> None:
    status, body = route(Atlas(tmp_path), "/", {}, NOW)
    assert status == 200
    assert b"<h1>Stores</h1>" in body
    assert b"certledger.coverage-index" not in body


def test_explore_data_prefers_the_harvest_variable(tmp_path: Path) -> None:
    assert explore_data(
        environ={"CERTLEDGER_DATA": "D:/data/certledger", "TRUSTATLAS_DATA": "D:/data/trustatlas"}
    ) == ("D:/data/certledger")
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "TRUSTATLAS_DATA=D:/data/trustatlas\nCERTLEDGER_DATA=D:/data/certledger\n",
        encoding="utf-8",
    )
    assert explore_data(environ={}, dotenv=dotenv) == "D:/data/certledger"
    assert explore_data(environ={}, dotenv=tmp_path / "missing.env") == "/data"
