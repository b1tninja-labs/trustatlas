"""The explore page reads artifacts and does not invent a section.

A stale `retrieved_at` is labelled stale, an unread store stays on the page, and a name that looks
like markup is escaped. The server itself is exercised once, on a loopback port, and then stopped.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

from explore import make_handler, route

NOW = datetime(2026, 11, 16, tzinfo=UTC)
A = "a" * 64


def write(path: Path, doc: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def data_dir(tmp_path: Path) -> Path:
    write(
        tmp_path / "store" / "curl.json",
        {
            "artifact": "trustatlas.bundle.collect",
            "program": "curl",
            "retrieved_at": "2020-01-01T00:00:00Z",
            "provenance": {"method": "fixture"},
            "certificates": [{"sha256": A, "subject": "<script>alert(1)</script>"}],
        },
    )
    write(
        tmp_path / "store" / "registry.status.json",
        {
            "artifact": "trustatlas.registry.status",
            "stores": [
                {
                    "id": "curl.mozilla_bundle",
                    "kind": "bundled",
                    "last_collection": {"artifact": "curl.json"},
                },
                {"id": "apple.security.framework", "kind": "os-store"},
            ],
        },
    )
    return tmp_path


def test_a_stale_store_is_labelled_and_an_unread_one_stays_listed(tmp_path: Path) -> None:
    from trustatlas import Atlas

    status, body = route(Atlas(data_dir(tmp_path)), "/", {}, NOW)
    page = body.decode()
    assert status == 200
    assert "apple.security.framework" in page
    assert "unread" in page
    assert "2020-01-01T00:00:00Z" in page
    assert "(stale)" in page
    assert "<script>alert" not in page
    assert "<h2>BGP" not in page
    assert "not sections" in page


def test_a_store_page_names_its_retrieved_at_and_refuses_a_path(tmp_path: Path) -> None:
    from trustatlas import Atlas

    atlas = Atlas(data_dir(tmp_path))
    status, body = route(atlas, "/store/curl.mozilla_bundle", {}, NOW)
    page = body.decode()
    assert status == 200
    assert "(stale)" in page
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert route(atlas, "/store/../curl.json", {}, NOW)[0] == 404
    refused, message = route(atlas, "/anchor", {"by": ["cert_sha256"], "q": ["nope"]}, NOW)
    assert refused == 400
    assert "64 hex" in message.decode()


def test_the_server_answers_the_inventory_and_then_stops(tmp_path: Path) -> None:
    from trustatlas import Atlas

    atlas = Atlas(data_dir(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(atlas, lambda: NOW))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
            page = response.read().decode()
            assert response.status == 200
        assert "curl.mozilla_bundle" in page
        assert "(stale)" in page
    finally:
        server.shutdown()
        thread.join(timeout=5)
