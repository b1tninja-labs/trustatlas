#!/usr/bin/env python3
"""Read-only HTML over artifacts already on disk.

Trust-store pages read what `Atlas` joins. When the data directory is a harvest
tree, `/` reads that instead: preserve cursors, heads, key censuses, CA catalogs,
the coverage index, and the log-list journal. Shard, tile, and certificate bytes
are named, not opened. A store the registry names and nobody collected is listed
`unread`. `retrieved_at` is always shown, and one older than `STALE_AFTER` is
labelled stale. Certificate bytes are not served: a row is a name and a digest.
"""

from __future__ import annotations

import argparse
import html
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from harvest_page import dispatch

from trustatlas import Atlas, AtlasError
from trustatlas.harvest import looks_like_harvest
from trustatlas.records import AnchorAnswer, Inventory, Store

STALE_AFTER = timedelta(days=14)
NOT_SECTIONS = ("BGP", "RPKI", "whois")


def parse_retrieved(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def freshness(retrieved_at: str | None, now: datetime) -> str:
    """`fresh`, `stale`, or `undated`. An unreadable timestamp is undated, never fresh."""
    parsed = parse_retrieved(retrieved_at)
    if parsed is None:
        return "undated"
    if now - parsed > STALE_AFTER:
        return "stale"
    return "fresh"


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, body: str, limits: tuple[str, ...]) -> bytes:
    omitted = ", ".join(NOT_SECTIONS)
    limit_items = "".join(f"<li>{_esc(item)}</li>" for item in limits)
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
body {{ font: 16px/1.45 system-ui, sans-serif; margin: 2rem; max-width: 72rem; color: #1c1917; }}
a {{ color: #1d4ed8; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #e7e5e4; vertical-align: top; }}
code {{ font-size: 0.85em; }}
.stale {{ color: #9a3412; font-weight: 600; }}
.undated {{ color: #9a3412; }}
.unread {{ color: #57534e; }}
form {{ display: flex; gap: 0.75rem; align-items: end; flex-wrap: wrap; margin: 1rem 0 1.5rem; }}
label {{ font-size: 0.9rem; }}
footer {{ margin-top: 2rem; color: #57534e; font-size: 0.9rem; }}
</style>
</head>
<body>
<p><a href="/stores">Stores</a> · <a href="/harvest">Harvest</a></p>
<h1>{_esc(title)}</h1>
<form action="/anchor" method="get">
<label><input type="radio" name="by" value="cert_sha256" checked> certificate SHA-256</label>
<label><input type="radio" name="by" value="spki_sha256"> SPKI SHA-256</label>
<label><input type="radio" name="by" value="subject"> name</label>
<label>Value <input name="q" required size="64"></label>
<button type="submit">Show stores</button>
</form>
{body}
<footer>
<p>Read from the data directory at request time. Nothing on this page is fetched, and nothing here is called trusted.</p>
<p>{_esc(omitted)} are not sections: this tree does not compute them.</p>
<ul>{limit_items}</ul>
</footer>
</body>
</html>
"""
    return document.encode("utf-8")


def render_inventory(inventory: Inventory, now: datetime) -> bytes:
    rows = []
    for store in inventory.stores:
        when = store.evidence.retrieved_at if store.evidence else None
        state = freshness(when, now)
        label = _esc(when) if when else "no retrieved_at"
        if store.read:
            name = f'<a href="/store/{_esc(store.id)}">{_esc(store.id)}</a>'
            count = _esc(store.anchors)
        else:
            name = f'<span class="unread">{_esc(store.id)}</span>'
            count = "unread"
        rows.append(
            "<tr>"
            f"<td>{name}</td>"
            f"<td>{_esc(store.role)}</td>"
            f"<td>{count}</td>"
            f'<td class="{state}">{label}' + (f" ({state})" if state != "fresh" else "") + "</td>"
            f"<td>{_esc(store.reason)}</td>"
            "</tr>"
        )
    body = (
        "<table><thead><tr><th>Store</th><th>Role</th><th>Anchors</th>"
        "<th>retrieved_at</th><th>Unread because</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return _page("Stores", body, inventory.limits)


def render_store(store: Store, now: datetime) -> bytes:
    when = store.evidence.retrieved_at
    state = freshness(when, now)
    rows = []
    for entry in store.entries:
        name = entry.subject or entry.alias or ""
        digest = entry.cert_sha256
        rows.append(
            "<tr>"
            f"<td>{_esc(name)}</td>"
            f'<td><a href="/anchor?by=cert_sha256&amp;q={_esc(digest)}"><code>{_esc(digest)}</code></a></td>'
            f"<td><code>{_esc(entry.spki_sha256 or '')}</code></td>"
            "</tr>"
        )
    body = (
        f'<p class="{state}">retrieved_at {_esc(when) or "absent"}'
        + (f" ({state})" if state != "fresh" else "")
        + f" · {_esc(store.evidence.path)} · <code>{_esc(store.evidence.sha256)}</code></p>"
        "<table><thead><tr><th>Name</th><th>Certificate SHA-256</th><th>SPKI SHA-256</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )
    return _page(store.id, body, ())


def render_anchor(answer: AnchorAnswer) -> bytes:
    field, value = answer.query
    rows = []
    for item in answer.answers:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.store)}</td>"
            f"<td>{_esc(item.state)}</td>"
            f"<td>{_esc(item.reason)}</td>"
            f"<td>{_esc(item.evidence.retrieved_at if item.evidence else '')}</td>"
            "</tr>"
        )
    body = (
        f"<p>Query <code>{_esc(field)}</code> <code>{_esc(value)}</code></p>"
        "<table><thead><tr><th>Store</th><th>State</th><th>Why unread</th>"
        "<th>retrieved_at</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )
    return _page("Anchor", body, answer.limits)


def explore_data(*, environ: dict[str, str] | None = None, dotenv: Path | None = None) -> str:
    """Data directory for the page: ``CERTLEDGER_DATA``, then ``TRUSTATLAS_DATA``, then ``.env``, then ``/data``."""
    env = os.environ if environ is None else environ
    for key in ("CERTLEDGER_DATA", "TRUSTATLAS_DATA"):
        found = env.get(key)
        if found:
            return found
    path = Path(__file__).resolve().parent.parent / ".env" if dotenv is None else dotenv
    return _from_dotenv(path) or "/data"


def _from_dotenv(path: Path) -> str | None:
    if not path.is_file():
        return None
    chosen: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key == "CERTLEDGER_DATA" and value:
            return value
        if key == "TRUSTATLAS_DATA" and value and chosen is None:
            chosen = value
    return chosen


def route(atlas: Atlas, path: str, query: dict[str, list[str]], now: datetime) -> tuple[int, bytes]:
    """One GET. Unknown paths are 404. A bad query is 400 and writes nothing."""
    if path in ("/", "/index.html") and looks_like_harvest(atlas.data):
        harvested = dispatch(atlas.data, "/harvest", query)
        if harvested is not None:
            return harvested
    if path in ("/", "/index.html", "/stores"):
        return 200, render_inventory(atlas.inventory(), now)
    harvested = dispatch(atlas.data, path, query)
    if harvested is not None:
        return harvested
    if path.startswith("/store/"):
        store_id = unquote(path.removeprefix("/store/"))
        if not store_id or "/" in store_id or store_id.startswith("."):
            return 404, _page("Not a store", "<p>That path is not a store id.</p>", ())
        try:
            store = atlas.store(store_id)
        except AtlasError as exc:
            return 404, _page("Unread", f"<p>{_esc(exc)}</p>", ())
        return 200, render_store(store, now)
    if path == "/anchor":
        by = (query.get("by") or ["cert_sha256"])[0]
        value = (query.get("q") or [""])[0]
        try:
            if by == "cert_sha256":
                answer = atlas.anchor(cert_sha256=value)
            elif by == "spki_sha256":
                answer = atlas.anchor(spki_sha256=value)
            elif by == "subject":
                answer = atlas.anchor(subject=value)
            else:
                raise AtlasError(f"by must be cert_sha256, spki_sha256 or subject, not {by!r}")
        except AtlasError as exc:
            return 400, _page("Query refused", f"<p>{_esc(exc)}</p>", ())
        return 200, render_anchor(answer)
    return 404, _page("Not found", "<p>No page at that path.</p>", ())


def make_handler(
    atlas: Atlas, clock: Callable[[], datetime] | None = None
) -> type[BaseHTTPRequestHandler]:
    def current() -> datetime:
        return datetime.now(UTC) if clock is None else clock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            split = urlsplit(self.path)
            query = parse_qs(split.query, keep_blank_values=True)
            status, body = route(atlas, split.path, query, current())
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
            return

    return Handler


def serve(atlas: Atlas, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(atlas))
    print(f"reading {atlas.data} at http://{host}:{port}/", flush=True)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=None)
    parser.add_argument("--bind", default="127.0.0.1:8080")
    args = parser.parse_args(argv)
    data = args.data or explore_data()
    host, _, port_text = args.bind.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        print(f"--bind must be host:port, not {args.bind!r}")
        return 2
    try:
        atlas = Atlas(data)
    except AtlasError as exc:
        print(exc)
        return 2
    try:
        serve(atlas, host or "127.0.0.1", port)
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
