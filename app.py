from __future__ import annotations

import html
import sqlite3
import sys
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from multiprocessing import freeze_support
from pathlib import Path
from urllib.parse import quote, urlparse

from flask import Flask, g, jsonify, redirect, render_template, request

from bulldog_engine import (
    BulldogDB,
    CacheLinkRenderer,
    canonicalize_url,
    process_url,
    wrap_document,
)

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "atlas_browser.db"
BULLDOG_DB_PATH = APP_DIR / "bulldog.sqlite3"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    visited_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_visited_at ON history(visited_at DESC);

CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bookmarks_created_at ON bookmarks(created_at DESC);
"""

_bulldog_db: BulldogDB | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def get_bulldog_db() -> BulldogDB:
    global _bulldog_db
    if _bulldog_db is None:
        _bulldog_db = BulldogDB(BULLDOG_DB_PATH)
    return _bulldog_db


@app.teardown_appcontext
def close_db(_exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    db.close()
    get_bulldog_db()


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return value
    if "." in value and " " not in value:
        return "https://" + value
    return "https://www.google.com/search?q=" + quote(value)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/browse")
def browse():
    url = normalize_url(request.args.get("url", ""))
    return redirect(url or "/")


# ---------------- Atlas history/bookmarks ----------------

@app.get("/api/history")
def history():
    rows = get_db().execute(
        "SELECT id, url, title, visited_at FROM history ORDER BY id DESC LIMIT 500"
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/history")
def add_history():
    data = request.get_json(silent=True) or {}
    url = normalize_url(str(data.get("url", "")))
    title = str(data.get("title", "")).strip() or url
    if not url.startswith(("http://", "https://")):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO history(url, title, visited_at) VALUES (?, ?, ?)",
        (url, title, utc_now()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.delete("/api/history")
def clear_history():
    db = get_db()
    db.execute("DELETE FROM history")
    db.commit()
    return jsonify({"ok": True})


@app.get("/api/bookmarks")
def bookmarks():
    rows = get_db().execute(
        "SELECT id, url, title, created_at FROM bookmarks ORDER BY id DESC"
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/bookmarks")
def add_bookmark():
    data = request.get_json(silent=True) or {}
    url = normalize_url(str(data.get("url", "")))
    title = str(data.get("title", "")).strip() or url
    if not url.startswith(("http://", "https://")):
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    db = get_db()
    db.execute(
        """
        INSERT INTO bookmarks(url, title, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET title=excluded.title
        """,
        (url, title, utc_now()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.delete("/api/bookmarks/<int:bookmark_id>")
def remove_bookmark(bookmark_id: int):
    db = get_db()
    db.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
    db.commit()
    return jsonify({"ok": True})


# ---------------- Bulldog integrated cache ----------------

@app.get("/bulldog")
def bulldog_index():
    db = get_bulldog_db()
    items = []
    for row in db.list_recent():
        label = row["title"] or row["url"]
        items.append(
            f'<li><a class="green-link" href="/bulldog/page/{row["id"]}">'
            f'{html.escape(label)}</a><br>'
            f'<small>{html.escape(row["url"])}</small></li>'
        )

    body = """
    <h1>Bulldog Cache</h1>
    <p>Integrated into Atlas Qt. Green links are sanitized cached pages;
       red links point to the live web.</p>
    <form action="/bulldog/process" method="get">
      <label>Process URL:
        <input name="url" size="70" placeholder="https://example.com/">
      </label>
      <input type="submit" value="Process">
    </form>
    <h2>Cached pages</h2><ul>
    """ + "\n".join(items) + "</ul>"

    toolbar = (
        '<div class="bulldog-bar"><strong>🐶 Bulldog + Atlas Qt</strong> &nbsp; '
        '<a href="/">Atlas Home</a></div>'
    )
    return wrap_document(body, "Bulldog Cache", toolbar)


@app.get("/bulldog/page/<int:page_id>")
def bulldog_page(page_id: int):
    db = get_bulldog_db()
    row = db.get_by_id(page_id)
    if not row:
        return wrap_document("<h1>Not found</h1>", "Bulldog"), 404

    renderer = CacheLinkRenderer(db)
    renderer.feed(row["sanitized_html"])
    renderer.close()

    update_q = urllib.parse.urlencode({"url": row["url"]})
    toolbar = (
        '<div class="bulldog-bar"><strong>🐶 Bulldog sanitized cache</strong> &nbsp; '
        '<a href="/">Atlas Home</a>'
        '<a href="/bulldog">Bulldog Cache</a>'
        f'<a href="/bulldog/update?{update_q}">Update this page</a>'
        f'<span class="bulldog-source">Source: {html.escape(row["url"])}</span>'
        '</div>'
    )
    return wrap_document(renderer.result(), row["title"] or row["url"], toolbar)


@app.get("/bulldog/process")
def bulldog_process():
    raw_url = request.args.get("url", "")
    try:
        url = canonicalize_url(raw_url)
        db = get_bulldog_db()
        existing = db.get_by_url(url)
        if existing:
            return redirect(f'/bulldog/page/{existing["id"]}')
        page_id = process_url(db, url)
        return redirect(f"/bulldog/page/{page_id}")
    except urllib.error.URLError as exc:
        return wrap_document(
            f"<h1>Fetch failed</h1><pre>{html.escape(str(exc))}</pre>",
            "Bulldog fetch failed",
        ), 502
    except Exception as exc:
        return wrap_document(
            f"<h1>Bulldog error</h1><pre>{html.escape(str(exc))}</pre>",
            "Bulldog error",
        ), 400


@app.get("/bulldog/update")
def bulldog_update():
    raw_url = request.args.get("url", "")
    try:
        url = canonicalize_url(raw_url)
        page_id = process_url(get_bulldog_db(), url)
        return redirect(f"/bulldog/page/{page_id}")
    except Exception as exc:
        return wrap_document(
            f"<h1>Bulldog update failed</h1><pre>{html.escape(str(exc))}</pre>",
            "Bulldog update failed",
        ), 400


@app.get("/api/bulldog/status")
def bulldog_status():
    db = get_bulldog_db()
    count = db.conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
    return jsonify({
        "ok": True,
        "pages": count,
        "database": str(BULLDOG_DB_PATH),
        "index": "/bulldog",
    })


@app.post("/api/bulldog/process")
def bulldog_process_api():
    data = request.get_json(silent=True) or {}
    raw_url = str(data.get("url", "")).strip()
    try:
        url = canonicalize_url(raw_url)
        db = get_bulldog_db()
        existing = db.get_by_url(url)
        page_id = int(existing["id"]) if existing else process_url(db, url)
        row = db.get_by_id(page_id)
        return jsonify({
            "ok": True,
            "page_id": page_id,
            "url": row["url"],
            "title": row["title"],
            "atlas_url": f"/bulldog/page/{page_id}",
            "cached": existing is not None,
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


if __name__ == "__main__":
    freeze_support()
    init_db()
    frozen = getattr(sys, "frozen", False)
    app.run(
        host="127.0.0.1",
        port=5055,
        debug=not frozen,
        use_reloader=not frozen,
    )
