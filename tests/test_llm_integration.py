"""Opt-in integration test against a local OpenAI-compatible LLM server.

Skipped unless both the ``openai`` SDK is importable AND a server answers at
``http://localhost:1234/v1`` (LM Studio's default). It exercises the real
provider -> HTTP -> model -> parse path, so it guards the integration without
mocking. It never runs in a normal CI environment (no server, no SDK -> skip).
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

_BASE = os.environ.get("KODA_TEST_LLM_BASE", "http://localhost:1234/v1")


def _reachable_model() -> str | None:
    try:
        import openai  # noqa: F401
    except ImportError:
        return None
    try:
        with urllib.request.urlopen(f"{_BASE}/models", timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError):  # URLError is OSError; JSONDecodeError is ValueError
        return None
    models = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict)]
    chat = [m for m in models if m and "embed" not in m.lower()]
    return (chat or models or [None])[0]


class LocalLLMIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.model = _reachable_model()
        if not self.model:
            self.skipTest("no local OpenAI-compatible LLM server (or openai SDK) available")
        os.environ["KODA_LLM"] = f"openai/{self.model}"
        os.environ["KODA_LLM_API_BASE"] = _BASE
        os.environ["KODA_LLM_API_KEY"] = "local-test"

    def test_json_mode_and_loopback_not_external(self):
        from security_scanner.ai import provider

        result = provider.complete(
            'Return exactly this JSON: {"ok": true}',
            system="Reply with strict JSON only.",
            json_mode=True,
            timeout_seconds=90,
        )
        self.assertTrue(result.text.strip())
        self.assertFalse(result.sent_externally)  # loopback base
        self.assertEqual(json.loads(result.text).get("ok"), True)


if __name__ == "__main__":
    unittest.main()
