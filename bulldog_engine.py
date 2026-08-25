from __future__ import annotations

import hashlib
import html
import sqlite3
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

USER_AGENT = "BulldogCache/0.2 (Atlas Qt integrated sanitized cache)"
MAX_FETCH_BYTES = 8 * 1024 * 1024

DROP_WITH_CONTENT = {
    "script", "style", "iframe", "object", "embed", "applet",
    "canvas", "svg", "noscript", "template",
}

UNWRAP_TAGS = {
    "form", "button", "input", "select", "option", "textarea",
    "video", "audio", "source",
}

ALLOWED_TAGS = {
    "html", "head", "body", "title", "div", "span", "p", "br", "hr",
    "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "dl",
    "dt", "dd", "table", "thead", "tbody", "tfoot", "tr", "th", "td",
    "blockquote", "pre", "code", "kbd", "samp", "strong", "b", "em",
    "i", "u", "small", "big", "sub", "sup", "a", "img",
}

GLOBAL_ALLOWED_ATTRS = {"title", "lang", "dir"}
TAG_ALLOWED_ATTRS = {
    "a": {"href", "name"},
    "img": {"src", "alt", "width", "height"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
    "table": {"summary"},
}
HTTP_SCHEMES = {"http", "https"}

CSS = """
body { font-family: Georgia, serif; max-width: 980px; margin: 1.5em auto;
       padding: 0 1em; line-height: 1.45; background: #f7f4ea; color: #111; }
a.green-link { color: #087a20; font-weight: bold; }
a.red-link { color: #a31414; }
a.process-link { color: #555; font-size: 80%; text-decoration: none; }
.bulldog-bar { border: 1px solid #777; background: #eee8d5; padding: .65em;
               margin-bottom: 1em; font-family: sans-serif; font-size: 90%; }
.bulldog-bar a { margin-right: 1em; }
.bulldog-source { overflow-wrap: anywhere; }
img { max-width: 100%; height: auto; }
"""

def now_ts() -> int:
    return int(time.time())

def canonicalize_url(url: str, base: Optional[str] = None) -> str:
    url = url.strip()
    if base:
        url = urllib.parse.urljoin(base, url)
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in HTTP_SCHEMES:
        raise ValueError(f"unsupported URL scheme: {scheme or '(none)'}")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("URL has no hostname")
    if parts.username:
        raise ValueError("URLs containing credentials are not accepted")
    port = parts.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if not port else f"{host}:{port}"
    path = parts.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, parts.query, ""))

def safe_remote_url(raw: str, base: Optional[str] = None) -> Optional[str]:
    try:
        return canonicalize_url(raw, base)
    except Exception:
        return None

class BulldogDB:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL DEFAULT '',
            sanitized_html TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_pages_url ON pages(url);
        """)
        self.conn.commit()

    def get_by_url(self, url: str):
        return self.conn.execute("SELECT * FROM pages WHERE url = ?", (url,)).fetchone()

    def get_by_id(self, page_id: int):
        return self.conn.execute("SELECT * FROM pages WHERE id = ?", (page_id,)).fetchone()

    def upsert(self, url: str, title: str, sanitized_html: str) -> int:
        digest = hashlib.sha256(sanitized_html.encode("utf-8", "replace")).hexdigest()
        ts = now_ts()
        row = self.get_by_url(url)
        if row:
            self.conn.execute("""
            UPDATE pages SET title=?, sanitized_html=?, content_sha256=?,
                             fetched_at=?, updated_at=? WHERE id=?
            """, (title, sanitized_html, digest, ts, ts, row["id"]))
            page_id = int(row["id"])
        else:
            cur = self.conn.execute("""
            INSERT INTO pages(url,title,sanitized_html,content_sha256,fetched_at,updated_at)
            VALUES (?,?,?,?,?,?)
            """, (url, title, sanitized_html, digest, ts, ts))
            page_id = int(cur.lastrowid)
        self.conn.commit()
        return page_id

    def list_recent(self, limit: int = 100):
        return self.conn.execute("""
        SELECT id,url,title,fetched_at FROM pages ORDER BY fetched_at DESC LIMIT ?
        """, (limit,)).fetchall()

class Sanitizer(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.out: list[str] = []
        self.drop_depth = 0
        self.title = ""
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.drop_depth:
            if tag in DROP_WITH_CONTENT:
                self.drop_depth += 1
            return
        if tag in DROP_WITH_CONTENT:
            self.drop_depth = 1
            return
        if tag in UNWRAP_TAGS or tag not in ALLOWED_TAGS:
            return
        if tag == "title":
            self.in_title = True

        clean_attrs = []
        allowed = GLOBAL_ALLOWED_ATTRS | TAG_ALLOWED_ATTRS.get(tag, set())
        for key, value in attrs:
            key = key.lower()
            if value is None or key.startswith("on") or key == "style" or key not in allowed:
                continue
            if tag == "a" and key == "href":
                target = safe_remote_url(value, self.base_url)
                if target:
                    clean_attrs.append(("href", target))
                continue
            if tag == "img" and key == "src":
                target = safe_remote_url(value, self.base_url)
                if target:
                    clean_attrs.append(("src", target))
                continue
            clean_attrs.append((key, value))

        rendered = "".join(
            f' {html.escape(k, quote=True)}="{html.escape(v, quote=True)}"'
            for k, v in clean_attrs
        )
        self.out.append(f"<{tag}{rendered}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.drop_depth:
            if tag in DROP_WITH_CONTENT:
                self.drop_depth -= 1
            return
        if tag in UNWRAP_TAGS or tag not in ALLOWED_TAGS:
            return
        if tag == "title":
            self.in_title = False
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self.drop_depth:
            return
        if self.in_title:
            self.title += data
        self.out.append(html.escape(data))

    def result(self) -> tuple[str, str]:
        return "".join(self.out), " ".join(self.title.split())

class CacheLinkRenderer(HTMLParser):
    """Render sanitized HTML using Atlas routes rather than a second Bulldog server."""

    def __init__(self, db: BulldogDB):
        super().__init__(convert_charrefs=True)
        self.db = db
        self.out: list[str] = []
        self.pending_process: list[Optional[str]] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs_dict = dict(attrs)
        if tag == "a" and attrs_dict.get("href"):
            href = attrs_dict["href"]
            cached = self.db.get_by_url(href)
            if cached:
                self.out.append(
                    f'<a class="green-link" href="/bulldog/page/{int(cached["id"])}" '
                    f'title="Sanitized cached page">'
                )
                self.pending_process.append(None)
            else:
                q = urllib.parse.urlencode({"url": href})
                self.out.append(
                    f'<a class="red-link" href="{html.escape(href, quote=True)}" '
                    f'title="LIVE WEB: not sanitized">'
                )
                self.pending_process.append(q)
            return

        rendered = "".join(
            f' {html.escape(k, quote=True)}="{html.escape(v, quote=True)}"'
            for k, v in attrs if v is not None
        )
        self.out.append(f"<{tag}{rendered}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        self.out.append(f"</{tag}>")
        if tag == "a" and self.pending_process:
            q = self.pending_process.pop()
            if q:
                self.out.append(
                    f' <a class="process-link" href="/bulldog/process?{q}">[process]</a>'
                )

    def handle_data(self, data):
        self.out.append(html.escape(data))

    def result(self) -> str:
        return "".join(self.out)

def fetch_page(url: str) -> tuple[str, str]:
    canonical = canonicalize_url(url)
    req = urllib.request.Request(canonical, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        final_url = canonicalize_url(resp.geturl())
        content_type = resp.headers.get_content_type()
        if content_type not in ("text/html", "application/xhtml+xml"):
            raise ValueError(f"not an HTML page: {content_type}")
        raw = resp.read(MAX_FETCH_BYTES + 1)
        if len(raw) > MAX_FETCH_BYTES:
            raise ValueError("page exceeds Bulldog MVP size limit")
        charset = resp.headers.get_content_charset() or "utf-8"
        try:
            text = raw.decode(charset, "replace")
        except LookupError:
            text = raw.decode("utf-8", "replace")
    return final_url, text

def process_url(db: BulldogDB, url: str) -> int:
    final_url, source = fetch_page(url)
    parser = Sanitizer(final_url)
    parser.feed(source)
    parser.close()
    sanitized, title = parser.result()
    return db.upsert(final_url, title or final_url, sanitized)

def wrap_document(body: str, title: str, toolbar: str = "") -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>{CSS}</style></head><body>{toolbar}{body}</body></html>"""
