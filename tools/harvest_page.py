"""HTML for the harvest tree. Certificate, shard, tile, and PEM bytes are not placed on the page."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlencode

from trustatlas.harvest import (
    CatalogSummary,
    FileStat,
    Harvest,
    HarvestError,
)

_ROOTS = frozenset({"harvest", "logs", "heads", "census", "catalogs", "coverage", "journal"})
_PAGE = 50
_NAV = (
    ("/harvest", "Harvest"),
    ("/logs", "Logs"),
    ("/heads", "Heads"),
    ("/census", "Key census"),
    ("/catalogs", "CA catalogs"),
    ("/coverage", "Coverage"),
    ("/journal", "Journal"),
    ("/stores", "Stores"),
)


def dispatch(data: Path, path: str, query: dict[str, list[str]]) -> tuple[int, bytes] | None:
    """Answer a harvest URL, or return None when ``path`` belongs to the store pages."""
    head = unquote(path.lstrip("/").split("/", 1)[0])
    if head not in _ROOTS:
        return None
    parts = _parts(path)
    if parts is None:
        return 404, _page(data, "Not found", "<p>That path is not in the harvest tree.</p>")
    try:
        harvest = Harvest(data)
    except HarvestError as exc:
        return 404, _page(data, "Harvest", f"<p>{_esc(exc)}</p>")
    try:
        return _answer(harvest, parts, query)
    except HarvestError as exc:
        return 404, _page(data, "Not found", f"<p>{_esc(exc)}</p>")


def _answer(harvest: Harvest, parts: list[str], query: dict[str, list[str]]) -> tuple[int, bytes]:
    name, *rest = parts
    if name == "harvest" and not rest:
        return 200, _home(harvest)
    if name == "logs" and not rest:
        return 200, _logs(harvest)
    if name == "logs" and len(rest) == 1:
        return 200, _log(harvest, rest[0])
    if name == "logs" and len(rest) == 2 and rest[1] in {"shards", "tiles", "issuers"}:
        return 200, _files_page(harvest, rest[0], rest[1], query)
    if name == "heads" and not rest:
        return 200, _heads(harvest)
    if name == "heads" and len(rest) == 1:
        return 200, _head(harvest, rest[0])
    if name == "census" and not rest:
        return 200, _censuses(harvest)
    if name == "census" and len(rest) == 1:
        return 200, _census(harvest, rest[0])
    if name == "catalogs" and not rest:
        return 200, _catalogs(harvest)
    if name == "catalogs" and len(rest) == 1:
        return 200, _catalog(harvest, rest[0], query)
    if name == "coverage" and not rest:
        return 200, _coverage(harvest)
    if name == "journal" and not rest:
        return 200, _journal(harvest)
    if name == "journal" and len(rest) == 1:
        return 200, _journal_day(harvest, rest[0])
    return 404, _page(harvest.data, "Not found", "<p>That path is not in the harvest tree.</p>")


def _home(harvest: Harvest) -> bytes:
    logs = []
    for slug in harvest.slugs("entries"):
        doc, error = harvest.cursor(slug)
        logs.append(_log_row(slug, doc, error))
    coverage, coverage_error = harvest.coverage()
    body = [
        _note(),
        "<h2>Logs</h2>",
        "<table><thead><tr><th>Log</th><th>Schema</th><th>State</th>"
        "<th>Cursor entries</th><th>Cursor tiles</th><th>Tree size</th><th>Updated</th></tr></thead><tbody>",
        *logs,
        "</tbody></table>",
        "<h2>Coverage</h2>",
        _coverage_blurb(coverage, coverage_error),
        "<h2>Heads</h2>",
        _slug_links("/heads", harvest.slugs("heads")),
        "<h2>Key census</h2>",
        _census_table(harvest),
        "<h2>CA catalogs</h2>",
        _catalog_table(harvest.catalog_names()),
        "<h2>Journal</h2>",
        _slug_links("/journal", harvest.slugs("journal")),
    ]
    return _page(harvest.data, "Harvest", "".join(body))


def _logs(harvest: Harvest) -> bytes:
    rows = []
    for slug in harvest.slugs("entries"):
        doc, error = harvest.cursor(slug)
        rows.append(_log_row(slug, doc, error))
    body = (
        _note()
        + "<table><thead><tr><th>Log</th><th>Schema</th><th>State</th><th>Cursor entries</th><th>Cursor tiles</th><th>Tree size</th><th>Updated</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    if not rows:
        body += "<p>No entries/ directory.</p>"
    return _page(harvest.data, "Logs", body)


def _log(harvest: Harvest, slug: str) -> bytes:
    harvest.ensure("entries", slug)
    doc, error = harvest.cursor(slug)
    checkpoint = harvest.checkpoint_size(slug)
    others = [item for item in harvest.direct_files(slug) if not item.name.endswith(".cle1")]
    bits = [
        f'<p><a href="/logs/{_esc(slug)}/shards">Shard files</a> · '
        f'<a href="/logs/{_esc(slug)}/tiles">Tile files</a> · '
        f'<a href="/logs/{_esc(slug)}/issuers">Issuer files</a></p>',
        _note(),
    ]
    if error:
        bits.append(f'<p class="unread">{_esc(error)}</p>')
    if doc is not None:
        bits.append(_render_doc(doc))
    if checkpoint is not None:
        bits.append(f"<p>checkpoint file {_fmt(checkpoint)} bytes, not opened</p>")
    if others:
        bits.append("<h2>Other files</h2>" + _file_table(others))
    return _page(harvest.data, slug, "".join(bits))


def _files_page(harvest: Harvest, slug: str, kind: str, query: dict[str, list[str]]) -> bytes:
    if kind == "shards":
        files = harvest.shards(slug)
        title = f"{slug} shards"
        blurb = "Shard bytes are not opened. A cursor counter is not a count of files."
    elif kind == "tiles":
        files = harvest.tiles(slug)
        title = f"{slug} tiles"
        blurb = "Tile bytes are not opened. A tile is not re-proved into the signed root here."
    else:
        files = harvest.issuers(slug)
        title = f"{slug} issuers"
        blurb = "Issuer DER is not parsed. The file name is the name stored on disk."
    needle = _query_text(query, "q")
    chosen = tuple(item for item in files if needle in item.name) if needle else files
    offset, limit = _window(query)
    page = chosen[offset : offset + limit]
    total_bytes = sum(item.size for item in chosen)
    action = f"/logs/{slug}/{kind}"
    body = (
        f"<p>{_esc(blurb)}</p>"
        f"<p>{_fmt(len(chosen))} files, {_fmt(total_bytes)} bytes"
        + (f", matching <code>{_esc(needle)}</code>" if needle else "")
        + ".</p>"
        f'<form method="get"><label>Name <input name="q" value="{_esc(needle)}" size="48"></label> '
        '<button type="submit">Filter</button></form>'
        + _pager(action, offset, limit, len(chosen), needle)
        + _file_table(page)
        + _pager(action, offset, limit, len(chosen), needle)
    )
    return _page(harvest.data, title, body)


def _heads(harvest: Harvest) -> bytes:
    rows = []
    for slug in harvest.slugs("heads"):
        try:
            files = harvest.head_files(slug)
        except HarvestError as exc:
            rows.append(f'<tr><td>{_esc(slug)}</td><td colspan="2">{_esc(exc)}</td></tr>')
            continue
        jsons = sum(1 for item in files if item.name.endswith(".json"))
        rows.append(
            "<tr>"
            f'<td><a href="/heads/{_esc(slug)}">{_esc(slug)}</a></td>'
            f"<td>{_fmt(jsons)} json</td>"
            f"<td>{_fmt(len(files))} files</td>"
            "</tr>"
        )
    body = (
        "<p>Signed tree heads. <code>.raw</code> is named and sized, not opened.</p>"
        "<table><thead><tr><th>Log</th><th>JSON</th><th>Files</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return _page(harvest.data, "Heads", body)


def _head(harvest: Harvest, slug: str) -> bytes:
    bits = ["<p><code>.raw</code> bytes are not opened.</p>", _file_table(harvest.head_files(slug))]
    for name, doc, error in harvest.head_documents(slug):
        bits.append(f"<h2>{_esc(name)}</h2>")
        if error:
            bits.append(f'<p class="unread">{_esc(error)}</p>')
        if doc is not None:
            bits.append(_render_doc(doc))
    return _page(harvest.data, slug, "".join(bits))


def _censuses(harvest: Harvest) -> bytes:
    return _page(harvest.data, "Key census", _census_table(harvest) + _census_note())


def _census(harvest: Harvest, slug: str) -> bytes:
    doc, error = harvest.census(slug)
    bits = [_census_note(), _file_table(harvest.census_files(slug))]
    if error:
        bits.append(f'<p class="unread">{_esc(error)}</p>')
    if doc is not None:
        bits.append(_render_doc(doc))
    return _page(harvest.data, slug, "".join(bits))


def _catalogs(harvest: Harvest) -> bytes:
    body = (
        "<p>CA catalog JSON. Certificate bytes stay in the file; this list is names and sizes.</p>"
        + _catalog_table(harvest.catalog_names())
    )
    return _page(harvest.data, "CA catalogs", body)


def _catalog(harvest: Harvest, name: str, query: dict[str, list[str]]) -> bytes:
    summary = harvest.catalog(name)
    needle = _query_text(query, "q").lower()
    rows = summary.rows
    if needle:
        rows = tuple(
            row for row in rows if needle in (row.spki_sha256 or "") or needle in (row.sha256 or "")
        )
    offset, limit = _window(query)
    body = _catalog_body(summary, rows, offset, limit, needle)
    return _page(harvest.data, name, body)


def _coverage(harvest: Harvest) -> bytes:
    doc, error = harvest.coverage()
    return _page(harvest.data, "Coverage", _coverage_body(doc, error))


def _journal(harvest: Harvest) -> bytes:
    body = (
        "<p>Log-list snapshots. The manifest is opened. Signature files are named and sized only.</p>"
        + _slug_links("/journal", harvest.slugs("journal"))
    )
    return _page(harvest.data, "Journal", body)


def _journal_day(harvest: Harvest, day: str) -> bytes:
    files, doc, error = harvest.journal_day(day)
    bits = [
        "<p>Signature files and the log-list documents are not parsed on this page. The manifest is.</p>",
        _file_table(files),
    ]
    if error:
        bits.append(f'<p class="unread">{_esc(error)}</p>')
    if doc is not None:
        bits.append("<h2>manifest.json</h2>" + _render_doc(doc))
    return _page(harvest.data, day, "".join(bits))


def _catalog_body(
    summary: CatalogSummary,
    rows: tuple[Any, ...],
    offset: int,
    limit: int,
    needle: str,
) -> str:
    bits = [
        "<p>Certificate bytes (<code>der_b64</code>) are not shown. "
        "An issuer edge is shown as the catalog recorded it.</p>"
    ]
    if summary.error:
        bits.append(f'<p class="unread">{_esc(summary.error)}</p>')
        return "".join(bits)
    kinds = ", ".join(f"{_esc(kind)} {_fmt(count)}" for kind, count in summary.edge_kinds) or "none"
    bits.append(
        "<p>"
        f"schema <code>{_esc(summary.schema)}</code> · written {_esc(summary.written_utc)} · "
        f"entries_read {_fmt(summary.entries_read)} · CAs {_fmt(summary.ca_count)} · "
        f"ca true {_fmt(summary.ca_true)} · psc true {_fmt(summary.psc_true)} · edges {kinds}"
        "</p>"
    )
    if summary.limits:
        bits.append("<ul>" + "".join(f"<li>{_esc(line)}</li>" for line in summary.limits) + "</ul>")
    if summary.logs:
        items = "".join(
            f"<li><code>{_esc(log_id)}</code> {_esc(url)}</li>" for log_id, url in summary.logs
        )
        bits.append(f"<ul>{items}</ul>")
    action = f"/catalogs/{summary.name}"
    shown = rows[offset : offset + limit]
    bits.append(
        f'<form method="get"><label>SPKI or certificate SHA-256 '
        f'<input name="q" value="{_esc(needle)}" size="64"></label> '
        '<button type="submit">Filter</button></form>'
        + _pager(action, offset, limit, len(rows), needle)
        + "<table><thead><tr><th>SPKI SHA-256</th><th>Certificate SHA-256</th><th>ca</th>"
        "<th>psc</th><th>DER bytes</th><th>Sightings</th><th>Issuers</th></tr></thead><tbody>"
    )
    for row in shown:
        issuer_text = ", ".join(
            f"{_esc(edge.kind)} <code>{_esc(edge.spki_sha256)}</code> ({_fmt(edge.showings)})"
            for edge in row.issuers
        )
        bits.append(
            "<tr>"
            f"<td><code>{_esc(row.spki_sha256)}</code></td>"
            f"<td><code>{_esc(row.sha256)}</code></td>"
            f"<td>{_esc(row.ca)}</td>"
            f"<td>{_esc(row.psc)}</td>"
            f"<td>{_fmt(row.der_bytes)}</td>"
            f"<td>{_fmt(row.sightings)}</td>"
            f"<td>{issuer_text}</td>"
            "</tr>"
        )
    bits.append("</tbody></table>" + _pager(action, offset, limit, len(rows), needle))
    return "".join(bits)


def _coverage_body(doc: dict[str, Any] | None, error: str | None) -> str:
    bits = [
        "<p>Read from <code>coverage/coverage-index-from-preserve.json</code>. "
        "An unwalked range is unread, not empty. <code>may_claim_absent</code> is the flag "
        "the file records.</p>"
    ]
    if error:
        bits.append(f'<p class="unread">{_esc(error)}</p>')
    if doc is None:
        return "".join(bits)
    limits = doc.get("limits")
    if isinstance(limits, list):
        bits.append(
            "<ul>"
            + "".join(f"<li>{_esc(line)}</li>" for line in limits if isinstance(line, str))
            + "</ul>"
        )
    logs = doc.get("logs")
    if not isinstance(logs, list):
        bits.append("<p>No logs list in this file.</p>")
        return "".join(bits)
    for row in logs:
        if not isinstance(row, dict):
            continue
        bits.append("<article>" + _coverage_row(row) + "</article>")
    schema = doc.get("schema")
    bits.append(f"<p>schema <code>{_esc(schema)}</code></p>")
    return "".join(bits)


def _coverage_row(row: dict[str, Any]) -> str:
    raw_head = row.get("head")
    head: dict[str, Any] = raw_head if isinstance(raw_head, dict) else {}
    held = _ranges(row.get("held"))
    unwalked = row.get("unwalked")
    gap_items = []
    if isinstance(unwalked, list):
        for gap in unwalked:
            if not isinstance(gap, dict):
                continue
            gap_items.append(
                "<li>"
                f"{_fmt(gap.get('start'))}-{_fmt(gap.get('end'))} "
                f"{_esc(gap.get('reason'))}: {_esc(gap.get('detail'))}"
                "</li>"
            )
    return (
        f"<h2>{_esc(row.get('origin'))}</h2>"
        f"<p>state {_esc(row.get('state'))} · complete {_esc(row.get('complete'))} · "
        f"may_claim_absent {_esc(row.get('may_claim_absent'))} · conflicted {_esc(row.get('conflicted'))} · "
        f"tree_size {_fmt(head.get('tree_size'))}</p>"
        f"<p>log_id <code>{_esc(row.get('log_id'))}</code> · root <code>{_esc(head.get('root_hash'))}</code> · "
        f"trust_class {_esc(head.get('trust_class'))}</p>"
        f"<p>held {held or 'none'}</p>"
        f"<ul>{''.join(gap_items)}</ul>"
    )


def _coverage_blurb(doc: dict[str, Any] | None, error: str | None) -> str:
    if error:
        return f'<p class="unread">{_esc(error)}</p> <p><a href="/coverage">Coverage</a></p>'
    if doc is None:
        return '<p><a href="/coverage">Coverage</a></p>'
    logs = doc.get("logs")
    count = len(logs) if isinstance(logs, list) else 0
    return f'<p><a href="/coverage">{_fmt(count)} logs in coverage-index-from-preserve.json</a></p>'


def _census_table(harvest: Harvest) -> str:
    rows = []
    for slug in harvest.slugs("leaf-shards"):
        doc, error = harvest.census(slug)
        if error or doc is None:
            rows.append(
                f'<tr><td><a href="/census/{_esc(slug)}">{_esc(slug)}</a></td>'
                f'<td colspan="3">{_esc(error or "unreadable")}</td></tr>'
            )
            continue
        rows.append(
            "<tr>"
            f'<td><a href="/census/{_esc(slug)}">{_esc(slug)}</a></td>'
            f"<td>{_fmt(doc.get('distinct_keys'))}</td>"
            f"<td>{_fmt(doc.get('entries_read'))}</td>"
            f"<td>{_esc(doc.get('written_utc'))}</td>"
            "</tr>"
        )
    if not rows:
        return "<p>No leaf-shards/ directory.</p>"
    return (
        "<table><thead><tr><th>Log</th><th>Distinct keys</th><th>Entries read</th>"
        "<th>Written</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _catalog_table(files: tuple[FileStat, ...]) -> str:
    if not files:
        return "<p>No ca-catalog JSON in artifacts/.</p>"
    rows = []
    for item in files:
        rows.append(
            "<tr>"
            f'<td><a href="/catalogs/{_esc(item.name)}">{_esc(item.name)}</a></td>'
            f"<td>{_fmt(item.size)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>File</th><th>Bytes</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _log_row(slug: str, doc: dict[str, Any] | None, error: str | None) -> str:
    if doc is None:
        return (
            f'<tr><td><a href="/logs/{_esc(slug)}">{_esc(slug)}</a></td>'
            f'<td colspan="6">{_esc(error or "no cursor")}</td></tr>'
        )
    tree = _tree_size(doc)
    return (
        "<tr>"
        f'<td><a href="/logs/{_esc(slug)}">{_esc(slug)}</a></td>'
        f"<td><code>{_esc(doc.get('schema'))}</code></td>"
        f"<td>{_esc(doc.get('state'))}</td>"
        f"<td>{_fmt(doc.get('entries_written'))}</td>"
        f"<td>{_fmt(doc.get('tiles_written'))}</td>"
        f"<td>{_fmt(tree)}</td>"
        f"<td>{_esc(doc.get('updated_utc'))}</td>"
        "</tr>"
    )


def _file_table(files: tuple[FileStat, ...] | list[FileStat]) -> str:
    if not files:
        return "<p>No files.</p>"
    rows = "".join(
        "<tr>"
        f"<td><code>{_esc(item.name)}</code></td>"
        f"<td>{_fmt(item.size)}</td>"
        "<td>bytes not shown</td>"
        "</tr>"
        for item in files
    )
    return (
        "<table><thead><tr><th>File</th><th>Bytes</th><th></th></tr></thead><tbody>"
        + rows
        + "</tbody></table>"
    )


def _slug_links(prefix: str, names: tuple[str, ...]) -> str:
    if not names:
        return "<p>None.</p>"
    return (
        "<ul>"
        + "".join(f'<li><a href="{prefix}/{_esc(name)}">{_esc(name)}</a></li>' for name in names)
        + "</ul>"
    )


def _render_doc(doc: dict[str, Any], depth: int = 0) -> str:
    """Render one JSON object. ``der_b64`` is omitted. Lists of records stop after a small cap."""
    if depth >= 4:
        return f"<p>{_fmt(len(doc))} fields</p>"
    scalars: list[tuple[str, object]] = []
    nested: list[str] = []
    for key in sorted(doc):
        value = doc[key]
        if key == "der_b64":
            scalars.append((key, "omitted"))
            continue
        if isinstance(value, dict):
            nested.append(f"<h3>{_esc(key)}</h3>{_render_doc(value, depth + 1)}")
        elif isinstance(value, list):
            nested.append(f"<h3>{_esc(key)}</h3>{_render_list(value, depth + 1)}")
        else:
            scalars.append((key, value))
    rows = []
    for key, value in scalars:
        shown = (
            _fmt(value) if isinstance(value, int) and not isinstance(value, bool) else _esc(value)
        )
        rows.append(f"<tr><td>{_esc(key)}</td><td>{shown}</td></tr>")
    table = "<table>" + "".join(rows) + "</table>" if rows else ""
    return table + "".join(nested)


def _render_list(value: list[Any], depth: int) -> str:
    if value and all(_is_range(item) for item in value):
        return "<p>" + ", ".join(f"{_fmt(item[0])}-{_fmt(item[1])}" for item in value) + "</p>"
    if value and all(isinstance(item, str) for item in value):
        return "<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in value) + "</ul>"
    if value and all(isinstance(item, dict) for item in value):
        if len(value) > 24:
            return f"<p>{_fmt(len(value))} objects</p>"
        return "".join(f"<article>{_render_doc(item, depth)}</article>" for item in value)
    return f"<p>{_fmt(len(value))} items</p>"


def _tree_size(doc: dict[str, Any]) -> int | None:
    for key in ("head", "checkpoint"):
        body = doc.get(key)
        if isinstance(body, dict):
            size = body.get("tree_size")
            if isinstance(size, int) and not isinstance(size, bool):
                return size
    return None


def _ranges(value: object) -> str:
    if not isinstance(value, list):
        return ""
    shown = []
    for item in value:
        if _is_range(item):
            shown.append(f"{_fmt(item[0])}-{_fmt(item[1])}")
    return ", ".join(shown)


def _is_range(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and isinstance(value[0], int)
        and not isinstance(value[0], bool)
        and isinstance(value[1], int)
        and not isinstance(value[1], bool)
    )


def _pager(action: str, offset: int, limit: int, total: int, needle: str) -> str:
    end = min(total, offset + limit)
    start = (offset + 1) if total and offset < total else 0
    bits = [f"<p>{_fmt(start)}-{_fmt(end)} of {_fmt(total)}"]
    extra = [("q", needle)] if needle else []
    if offset > 0:
        query = urlencode([*extra, ("offset", str(max(0, offset - limit))), ("limit", str(limit))])
        bits.append(f' · <a href="{action}?{query}">Previous</a>')
    if offset + limit < total:
        query = urlencode([*extra, ("offset", str(offset + limit)), ("limit", str(limit))])
        bits.append(f' · <a href="{action}?{query}">Next</a>')
    bits.append("</p>")
    return "".join(bits)


def _window(query: dict[str, list[str]]) -> tuple[int, int]:
    return _query_int(query, "offset", 0, 0, 10_000_000), _query_int(query, "limit", _PAGE, 1, 200)


def _query_int(query: dict[str, list[str]], name: str, default: int, lo: int, hi: int) -> int:
    raws = query.get(name)
    raw = raws[0] if raws else None
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(hi, max(lo, value))


def _query_text(query: dict[str, list[str]], name: str) -> str:
    raw = (query.get(name) or [""])[0]
    return raw.strip()[:128]


def _parts(path: str) -> list[str] | None:
    parts = []
    for piece in path.split("/"):
        if piece == "":
            continue
        name = unquote(piece)
        if name in {".", ".."} or "/" in name or "\\" in name:
            return None
        parts.append(name)
    return parts


def _note() -> str:
    return (
        "<p>JSON artifacts and file names are read from this directory. "
        "Shard, tile, and certificate bytes stay closed. "
        "An unwalked index is unread, not empty.</p>"
    )


def _census_note() -> str:
    return (
        "<p><code>key-census.json</code> is opened. "
        "<code>unscreenable.pem</code>, <code>census-state.json</code>, and the sources file are not opened. "
        "No weak-key verdict is produced here.</p>"
    )


def _page(data: Path, title: str, body: str) -> bytes:
    links = " ".join(f'<a href="{href}">{label}</a>' for href, label in _NAV)
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
body {{ font: 16px/1.45 system-ui, sans-serif; margin: 2rem; max-width: 80rem; color: #1c1917; }}
nav a {{ margin-right: 0.85rem; }}
a {{ color: #1d4ed8; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem; }}
th, td {{ text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #e7e5e4; vertical-align: top; }}
code {{ font-size: 0.85em; }}
article {{ border-top: 1px solid #e7e5e4; padding: 0.4rem 0; }}
.unread {{ color: #9a3412; }}
footer {{ margin-top: 2rem; color: #57534e; font-size: 0.9rem; }}
</style>
</head>
<body>
<nav>{links}</nav>
<h1>{_esc(title)}</h1>
<p>Data directory <code>{_esc(data)}</code></p>
{body}
<footer>
<p>Read from the data directory at request time. Nothing on this page is fetched, and nothing here is called trusted.</p>
</footer>
</body>
</html>
"""
    return document.encode("utf-8")


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _fmt(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        return _esc(value)
    return f"{value:,}"
