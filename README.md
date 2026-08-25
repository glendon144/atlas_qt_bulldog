# Atlas Qt + Bulldog integration

This is a source-first integration of Bulldog into the Atlas Qt Flask backend.

## Files

- `app.py` — Atlas backend with integrated Bulldog routes.
- `bulldog_engine.py` — Bulldog sanitizer/cache engine without its own HTTP server.
- `original_app.py` — uploaded Atlas backend, unchanged.
- `original_bulldog.py` — uploaded Bulldog MVP, unchanged.

Your existing `templates/index.html` is intentionally not replaced.

## What changes

Atlas continues listening on:

    http://127.0.0.1:5055/

Bulldog is now available inside the same process at:

    http://127.0.0.1:5055/bulldog

The cache database is:

    bulldog.sqlite3

next to `app.py`.

### Routes

- `/bulldog` — cache index
- `/bulldog/process?url=https://...` — sanitize/cache a page
- `/bulldog/page/<id>` — display sanitized cached page
- `/bulldog/update?url=https://...` — refresh cached page
- `/api/bulldog/status` — JSON cache status
- `POST /api/bulldog/process` with `{"url":"https://..."}` — API for future Qt/JS toolbar integration

Green links point to pages already in the Bulldog database.
Red links point to the live web and get a `[process]` action.

## Install into a copy of the Atlas project

From your Atlas project directory, make a backup first. Then copy:

    cp app.py app.py.pre-bulldog
    cp /path/to/atlas_qt_bulldog/app.py .
    cp /path/to/atlas_qt_bulldog/bulldog_engine.py .

Keep your existing `templates/` directory.

Run the browser exactly as you currently do. No Bulldog server on port 8766 is needed.

## First test

Open:

    http://127.0.0.1:5055/bulldog

Process a harmless public URL. Then click an uncached red link's `[process]` action and verify that it becomes a cached green destination.

## Next UI step

The backend deliberately includes `POST /api/bulldog/process`. Once the Qt/browser-side source or `templates/index.html` is available, a toolbar button can send the current URL there and navigate the current tab to the returned `atlas_url`.

## Security note

This preserves the original Bulldog MVP's design and limitations. It is not yet a hardened hostile-content isolation boundary. In particular, a production version still needs explicit SSRF/internal-network protections and stricter fetch/resource policy.


## v0.2 Atlas shell integration

This version also includes `templates/index.html` with:

- a 🐶 Bulldog item in the Atlas sidebar
- a Bulldog panel with a direct sanitize/process form
- a home-page quick link to the Bulldog cache
- links to the cache index and JSON cache status

It intentionally uses ordinary links/forms, so the Bulldog controls work even before any custom Qt/JavaScript toolbar wiring is added.
