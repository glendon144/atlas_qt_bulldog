import tempfile
import unittest
from unittest.mock import patch

import app as atlas
from bulldog_engine import BulldogDB, CacheLinkRenderer, FetchPolicy, PolicyRedirectHandler, process_url


class BulldogHardeningTests(unittest.TestCase):
    def setUp(self):
        self.client = atlas.app.test_client()

    def token(self):
        return {"csrf_token": atlas._CSRF_TOKEN}

    def test_default_policy_preserves_local_and_public_destinations(self):
        policy = FetchPolicy()
        for url in (
            "http://localhost:5055/atlas-universe",
            "http://127.0.0.1:5055/",
            "http://192.168.1.20/wiki",
            "http://100.64.0.2/tailscale",
            "https://example.com/",
        ):
            self.assertEqual(policy.validate(url), url)

    def test_restrictive_policy_applies_to_redirects(self):
        policy = FetchPolicy(["localhost", "127.0.0.1"])
        self.assertEqual(policy.validate("http://localhost/a"), "http://localhost/a")
        with self.assertRaises(ValueError):
            policy.validate("https://example.com/")
        handler = PolicyRedirectHandler(policy)
        self.assertEqual(policy.validate("http://localhost/final"), "http://localhost/final")
        with self.assertRaises(ValueError):
            handler.redirect_request(None, None, 302, "Found", {}, "https://example.com/")

    def test_processes_public_local_private_and_atlas_urls(self):
        with tempfile.NamedTemporaryFile() as database, patch(
            "bulldog_engine.fetch_page", side_effect=lambda url, policy: (policy.validate(url), "<p>safe</p>")
        ):
            db = BulldogDB(database.name)
            for url in (
                "https://example.com/public",
                "http://localhost:5055/atlas-universe",
                "http://192.168.1.20/private-lan",
            ):
                page_id = process_url(db, url, FetchPolicy())
                self.assertEqual(db.get_by_id(page_id)["url"], url)

    def test_green_and_red_links_remain_distinct(self):
        with tempfile.NamedTemporaryFile() as database:
            db = BulldogDB(database.name)
            cached_id = db.upsert("http://localhost/cached", "Cached", "<p>cached</p>")
            renderer = CacheLinkRenderer(db)
            renderer.feed(
                f'<a href="http://localhost/cached">green</a>'
                '<a href="http://localhost/live">red</a>'
            )
            output = renderer.result()
        self.assertIn(f'/bulldog/page/{cached_id}', output)
        self.assertIn('href="http://localhost/live"', output)
        self.assertIn('method="post" action="/bulldog/process"', output)
        self.assertIn('name="url" value="http://localhost/live"', output)

    def test_html_process_form_reads_posted_url(self):
        with patch.object(atlas, "process_url", return_value=7), patch.object(
            atlas.BulldogDB, "get_by_url", return_value=None
        ), patch.object(
            atlas.BulldogDB, "get_by_id", return_value={"id": 7, "url": "http://localhost/live", "title": "Live"}
        ):
            response = self.client.post(
                "/bulldog/process", data={"url": "http://localhost/live", **self.token()}
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/bulldog/page/7")

    def test_fetch_command_requires_csrf_token(self):
        response = self.client.post("/api/bulldog/process", json={"url": "http://localhost/"})
        self.assertEqual(response.status_code, 403)

    def test_valid_ui_fetch_command_succeeds(self):
        with patch.object(atlas, "process_url", return_value=7), patch.object(
            atlas.BulldogDB, "get_by_url", return_value=None
        ), patch.object(
            atlas.BulldogDB, "get_by_id", return_value={"id": 7, "url": "http://localhost/", "title": "Local"}
        ):
            response = self.client.post(
                "/api/bulldog/process", json={"url": "http://localhost/"}, headers={"X-Bulldog-CSRF": atlas._CSRF_TOKEN}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["page_id"], 7)

    def test_display_routes_remain_get_and_cached_page_renders(self):
        with patch.object(atlas.BulldogDB, "list_recent", return_value=[]):
            self.assertEqual(self.client.get("/bulldog").status_code, 200)
        with patch.object(
            atlas.BulldogDB, "get_by_id", return_value={"id": 1, "url": "http://localhost/", "title": "Local", "sanitized_html": "<p>Hello</p>"}
        ):
            response = self.client.get("/bulldog/page/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hello", response.data)

    def test_non_loopback_binding_requires_remote_token(self):
        old_host, old_token = atlas.HOST, atlas.REMOTE_AUTH_TOKEN
        try:
            atlas.HOST = "0.0.0.0"
            atlas.REMOTE_AUTH_TOKEN = "remote-secret"
            with patch.object(atlas, "process_url", return_value=7):
                response = self.client.post(
                    "/api/bulldog/process", json={"url": "http://localhost/"}, headers={"X-Bulldog-CSRF": atlas._CSRF_TOKEN}
                )
            self.assertEqual(response.status_code, 403)
            with patch.object(atlas, "process_url", return_value=7), patch.object(
                atlas.BulldogDB, "get_by_url", return_value=None
            ), patch.object(
                atlas.BulldogDB, "get_by_id", return_value={"id": 7, "url": "http://localhost/", "title": "Local"}
            ):
                response = self.client.post(
                    "/api/bulldog/process", json={"url": "http://localhost/"},
                    headers={"X-Bulldog-CSRF": atlas._CSRF_TOKEN, "Authorization": "Bearer remote-secret"},
                )
            self.assertEqual(response.status_code, 200)
        finally:
            atlas.HOST, atlas.REMOTE_AUTH_TOKEN = old_host, old_token


if __name__ == "__main__":
    unittest.main()
