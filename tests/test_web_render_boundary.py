from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import web


class RenderBoundaryTests(unittest.TestCase):
    def _render_with_fake_browser(self, requests, *, fetch_status=200, supports_websocket=True, **kwargs):
        observed = {"fetches": [], "aborts": [], "context_headers": [], "routes": [], "websockets": []}

        class Route:
            def __init__(self, url):
                self.request = types.SimpleNamespace(url=url, method="GET", headers={"accept": "text/html"})

            def fetch(self, **options):
                observed["fetches"].append((self.request.url, options))
                return types.SimpleNamespace(status=fetch_status)

            def fulfill(self, **_options):
                pass

            def abort(self):
                observed["aborts"].append(self.request.url)

            def continue_(self):
                observed["routes"].append(self.request.url)

        class Page:
            def __init__(self, context):
                self.context = context

            def goto(self, _url, **_options):
                for requested in requests:
                    self.context.callback(Route(requested))

            def content(self):
                return "<html>rendered</html>"

        class Context:
            def __init__(self):
                if not supports_websocket:
                    self.route_web_socket = None

            def route_web_socket(self, pattern, callback):
                observed["websockets"].append((pattern, callback))

            def route(self, _pattern, callback):
                self.callback = callback

            def on(self, *_args):
                pass

            def add_cookies(self, _cookies):
                pass

            def set_extra_http_headers(self, headers):
                observed["context_headers"].append(headers)

            def new_page(self):
                return Page(self)

            def cookies(self):
                return []

        class Browser:
            def new_context(self, **_options):
                return Context()

            def close(self):
                pass

        class SyncPlaywright:
            def __enter__(self):
                return types.SimpleNamespace(chromium=types.SimpleNamespace(launch=lambda **_options: Browser()))

            def __exit__(self, *_args):
                pass

        package = types.ModuleType("playwright")
        api = types.ModuleType("playwright.sync_api")
        api.Error = RuntimeError
        api.sync_playwright = SyncPlaywright
        package.sync_api = api
        with patch.dict(sys.modules, {"playwright": package, "playwright.sync_api": api}), \
             patch.object(web, "_ensure_bundled_browsers_path"):
            result = web._render_page(requests[0], timeout=1, **kwargs)
        return result, observed

    def test_credentialed_render_fetches_one_hop_and_aborts_cross_origin_redirect(self):
        source = "https://source.example/page"
        external = "https://other.example/landing"
        result, observed = self._render_with_fake_browser(
            [source, external], extra_headers={"Authorization": "Bearer secret"},
            allowed_origins={"https://source.example"},
        )
        self.assertIsNone(result[0])
        self.assertEqual([url for url, _ in observed["fetches"]], [source])
        self.assertEqual(observed["fetches"][0][1]["max_redirects"], 0)
        self.assertEqual(observed["fetches"][0][1]["headers"]["Authorization"], "Bearer secret")
        self.assertEqual(observed["aborts"], [external])
        self.assertEqual(observed["context_headers"], [])

    def test_credentialed_same_origin_render_remains_available(self):
        source = "https://source.example/page"
        result, observed = self._render_with_fake_browser(
            [source], extra_headers={"Authorization": "Bearer secret"},
            allowed_origins={"https://source.example"},
        )
        self.assertEqual(result[0], "<html>rendered</html>")
        self.assertEqual(len(observed["fetches"]), 1)
        self.assertEqual(observed["aborts"], [])
        self.assertEqual(observed["websockets"][0][0], "**/*")
        socket_route = types.SimpleNamespace(close=lambda: observed["websockets"].append("closed"))
        observed["websockets"][0][1](socket_route)
        self.assertEqual(observed["websockets"][-1], "closed")

    def test_renderer_without_websocket_interception_fails_closed(self):
        result, observed = self._render_with_fake_browser(
            ["https://source.example/page"], supports_websocket=False,
            extra_headers={"Authorization": "Bearer secret"},
        )
        self.assertIsNone(result[0])
        self.assertIn("WebSocket", result[3])
        self.assertEqual(observed["fetches"], [])

    def test_render_aborts_redirect_even_without_custom_credentials(self):
        source = "https://source.example/page"
        result, observed = self._render_with_fake_browser(
            [source], fetch_status=302, allowed_origins={"https://source.example"},
        )
        self.assertIsNone(result[0])
        self.assertEqual(observed["aborts"], [source])
        self.assertEqual(observed["fetches"][0][1]["max_redirects"], 0)

    def test_approved_cross_origin_render_does_not_inherit_custom_headers(self):
        source = "https://source.example/page"
        allowed_asset = "https://asset.example/style.css"
        result, observed = self._render_with_fake_browser(
            [source, allowed_asset], extra_headers={"Authorization": "Bearer secret"},
            allowed_origins={"https://source.example", "https://asset.example"},
        )
        self.assertEqual(result[0], "<html>rendered</html>")
        self.assertEqual(observed["fetches"][0][1]["headers"]["Authorization"], "Bearer secret")
        self.assertNotIn("Authorization", observed["fetches"][1][1]["headers"])

    def test_network_context_keeps_its_policy_path(self):
        source = "https://source.example/page"

        class Network:
            def __init__(self):
                self.authorized = []

            def browser_launch_options(self):
                return {"headless": True}

            def browser_context_options(self):
                return {"service_workers": "block"}

            def authorize_url(self, url, *, method, reserve):
                self.authorized.append((url, method))

            def remaining_timeout(self):
                return 1

        network = Network()
        with patch.object(web, "_pinned_render_response", return_value=(200, {}, b"ok")) as pinned:
            result, observed = self._render_with_fake_browser(
                [source], extra_headers={"Authorization": "Bearer secret"},
                allowed_origins={"https://source.example"}, network_context=network,
            )
        self.assertEqual(result[0], "<html>rendered</html>")
        self.assertEqual(network.authorized, [(source, "GET")])
        self.assertEqual(observed["routes"], [])
        self.assertEqual(observed["fetches"], [])
        self.assertEqual(observed["context_headers"], [])
        pinned.assert_called_once()
        self.assertEqual(pinned.call_args.args[2], {"Authorization": "Bearer secret"})

    def test_network_context_rejects_redirect_before_browser_follows_it(self):
        source = "https://source.example/page"

        class Network:
            def browser_launch_options(self):
                return {"headless": True}

            def browser_context_options(self):
                return {"service_workers": "block"}

            def authorize_url(self, _url, *, method, reserve):
                self.assertion = (method, reserve)

            def remaining_timeout(self):
                return 1

        network = Network()
        with patch.object(web, "_pinned_render_response", return_value=None):
            result, observed = self._render_with_fake_browser(
                [source], allowed_origins={"https://source.example"}, network_context=network,
            )
        self.assertIsNone(result[0])
        self.assertEqual(network.assertion, ("GET", False))
        self.assertEqual(observed["aborts"], [source])


if __name__ == "__main__":
    unittest.main()
