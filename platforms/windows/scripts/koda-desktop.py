"""PyInstaller entry point for the KODA single-window desktop app.

Unlike ``koda-app.py`` (which prints to a console window and opens the system
web browser), this entry point:

  1. Starts the local KODA dashboard server on a background daemon thread.
  2. Hosts the dashboard inside ONE native desktop window (Edge WebView2 on
     Windows) via pywebview -- no terminal window, no separate browser tab.

This mirrors the macOS KODA app, which is a single native window. If the native
webview runtime is unavailable, it falls back to opening the default browser so
the user is never left without the dashboard.
"""
from __future__ import annotations

import argparse
import os
import platform
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

shared_engine = Path(__file__).resolve().parents[3] / "platforms" / "shared" / "python"
if shared_engine.exists():
    sys.path.insert(0, str(shared_engine))

from security_scanner.app import _create_available_server
from security_scanner.server import DEFAULT_HOST, DEFAULT_PORT, create_dashboard_server, dashboard_url

WINDOW_MIN_WIDTH = 980
WINDOW_MIN_HEIGHT = 720


def _set_safe_working_directory() -> None:
    """Start from the user's home folder instead of the installer directory."""
    try:
        os.chdir(Path.home().resolve())
    except Exception:
        pass


def _start_dashboard_server(host: str, port: int, language: str) -> str:
    """Bind the dashboard server and serve it on a background daemon thread."""
    resolved_port, server = _create_available_server(host, port, language, 20)
    url = dashboard_url(host, resolved_port)

    thread = threading.Thread(target=server.serve_forever, name="koda-dashboard", daemon=True)
    thread.start()
    return url


def _run_native_window(url: str, display_name: str) -> bool:
    """Show the dashboard in a single native window. Return False if unavailable."""
    if platform.system() == "Windows" and not _windows_webview2_runtime_available():
        return False

    try:
        import webview  # type: ignore
    except Exception:
        return False

    try:
        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.create_window(
            display_name,
            url=url,
            width=1180,
            height=860,
            min_size=(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT),
            text_select=True,
        )
        # gui=None lets pywebview auto-select the best backend
        # (Edge WebView2 on Windows, WebKit on macOS, GTK/Qt on Linux).
        webview.start()
        return True
    except Exception:
        return False


def _windows_webview2_runtime_available() -> bool:
    """Return whether the Evergreen WebView2 Runtime appears installed."""
    try:
        import winreg
    except Exception:
        return False

    runtime_id = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    subkey = rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{runtime_id}"
    roots = (
        (winreg.HKEY_CURRENT_USER, 0),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
    )

    for root, flags in roots:
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | flags) as key:
                version, _ = winreg.QueryValueEx(key, "pv")
                if str(version).strip():
                    return True
        except OSError:
            continue
    return False


def _run_browser_mode(url: str) -> int:
    webbrowser.open(url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


def _smoke_test_dashboard(language: str) -> int:
    """Verify packaged imports and HTTP startup without opening a user window."""
    with create_dashboard_server(DEFAULT_HOST, 0, language) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = dashboard_url(DEFAULT_HOST, server.server_address[1])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=10) as response:
                return 0 if response.status == 200 and b"KODA" in response.read() else 1
        finally:
            server.shutdown()
            thread.join(timeout=5)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run KODA desktop dashboard.")
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Skip the native WebView window and open KODA in the default browser.",
    )
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_args(sys.argv[1:])
    if args.smoke_test:
        return _smoke_test_dashboard(os.environ.get("KODA_LANGUAGE", "ko"))
    display_name = os.environ.setdefault("KODA_DISPLAY_NAME", "KODA")
    _set_safe_working_directory()

    host = os.environ.get("KODA_HOST", DEFAULT_HOST)
    port = int(os.environ.get("KODA_PORT", DEFAULT_PORT))
    language = os.environ.get("KODA_LANGUAGE", "ko")

    url = _start_dashboard_server(host, port, language)

    if args.browser or os.environ.get("KODA_BROWSER_MODE") == "1":
        return _run_browser_mode(url)

    if _run_native_window(url, display_name):
        return 0

    # Fallback: the native webview runtime is missing. Open the browser so the
    # dashboard is still reachable, then keep the server alive.
    return _run_browser_mode(url)


if __name__ == "__main__":
    raise SystemExit(main())
