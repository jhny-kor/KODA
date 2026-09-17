"""Minimal LLM provider abstraction (opt-in).

A single ``complete()`` entry point dispatches to a backend selected by the ``KODA_LLM``
environment variable (or an explicit ``model`` argument), using the same provider-prefix
convention as comparable tools: ``ollama/<model>``, ``anthropic/<model>``, ``openai/<model>``.

Design constraints that keep KODA's identity intact:
- The local **ollama** backend uses only the standard library (``urllib``) and never sends
  data off the machine (``sent_externally=False``).
- Cloud backends (anthropic, openai) are **lazy-imported optional extras**; if the SDK is
  missing the call raises :class:`LLMUnavailable` instead of crashing the scan.
- Failures never propagate as arbitrary exceptions: callers catch :class:`LLMUnavailable`
  and degrade gracefully (the scan continues without triage).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


DEFAULT_OLLAMA_BASE = "http://localhost:11434"
_MAX_TOKENS = 1024


@dataclass(frozen=True)
class LLMResult:
    text: str
    backend: str
    # True when the request left the local machine (cloud backends). Used to surface a
    # one-time privacy warning to the user.
    sent_externally: bool


class LLMUnavailable(RuntimeError):
    """Raised when no usable LLM backend is configured or a request fails."""


def resolve_model(explicit: str | None = None) -> str:
    model = (explicit or os.environ.get("KODA_LLM", "")).strip()
    if not model:
        raise LLMUnavailable(
            "No LLM configured. Set KODA_LLM or pass --llm, e.g. 'ollama/qwen2.5-coder:7b'."
        )
    return model


def complete(
    prompt: str,
    *,
    system: str = "",
    json_mode: bool = False,
    model: str | None = None,
    timeout_seconds: float = 30.0,
) -> LLMResult:
    """Return a completion from the configured backend.

    Raises :class:`LLMUnavailable` for any configuration or transport problem so callers
    can degrade gracefully.
    """
    spec = resolve_model(model)
    backend, _, name = spec.partition("/")
    backend = backend.strip().lower()
    name = name.strip()
    if not name:
        raise LLMUnavailable(
            f"Invalid KODA_LLM '{spec}'. Use '<backend>/<model>' such as 'ollama/qwen2.5-coder:7b'."
        )
    if backend == "ollama":
        return _complete_ollama(name, prompt, system=system, json_mode=json_mode, timeout_seconds=timeout_seconds)
    if backend == "anthropic":
        return _complete_anthropic(name, prompt, system=system, timeout_seconds=timeout_seconds)
    if backend == "openai":
        return _complete_openai(name, prompt, system=system, timeout_seconds=timeout_seconds)
    raise LLMUnavailable(
        f"Unsupported LLM backend '{backend}'. Supported backends: ollama, anthropic, openai."
    )


def _complete_ollama(
    model: str,
    prompt: str,
    *,
    system: str,
    json_mode: bool,
    timeout_seconds: float,
) -> LLMResult:
    base = _ollama_base(os.environ.get("KODA_LLM_API_BASE", DEFAULT_OLLAMA_BASE))
    payload: dict[str, object] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
    }
    if system:
        payload["system"] = system
    if json_mode:
        payload["format"] = "json"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/api/generate",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "koda-local-security-scanner"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        raise LLMUnavailable(f"Local Ollama request failed ({base}): {exc}") from exc
    text = str(data.get("response", "")).strip() if isinstance(data, dict) else ""
    return LLMResult(text=text, backend="ollama", sent_externally=False)


def _ollama_base(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    try:
        parsed.port
    except ValueError as exc:
        raise LLMUnavailable("KODA_LLM_API_BASE must use a valid HTTP(S) port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise LLMUnavailable("KODA_LLM_API_BASE must be an HTTP(S) URL without credentials or query data")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _complete_anthropic(model: str, prompt: str, *, system: str, timeout_seconds: float) -> LLMResult:
    try:
        import anthropic
    except ImportError as exc:  # optional extra
        raise LLMUnavailable(
            "The anthropic SDK is not installed. Install it with: pip install 'koda[ai]' (or pip install anthropic)."
        ) from exc
    api_key = os.environ.get("KODA_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMUnavailable("Set KODA_LLM_API_KEY (or ANTHROPIC_API_KEY) to use the anthropic backend.")
    try:
        client = anthropic.Anthropic(api_key=api_key, timeout=timeout_seconds)
        message = client.messages.create(
            model=model,
            max_tokens=_MAX_TOKENS,
            system=system or anthropic.NOT_GIVEN,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(
            getattr(block, "text", "") for block in message.content if getattr(block, "type", "") == "text"
        ).strip()
    except LLMUnavailable:
        raise
    except Exception as exc:  # SDK/transport errors converted to a uniform failure
        raise LLMUnavailable(f"Anthropic request failed: {exc}") from exc
    return LLMResult(text=text, backend="anthropic", sent_externally=True)


def _complete_openai(model: str, prompt: str, *, system: str, timeout_seconds: float) -> LLMResult:
    try:
        import openai
    except ImportError as exc:  # optional extra
        raise LLMUnavailable(
            "The openai SDK is not installed. Install it with: pip install 'koda[ai]' (or pip install openai)."
        ) from exc
    api_key = os.environ.get("KODA_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise LLMUnavailable("Set KODA_LLM_API_KEY (or OPENAI_API_KEY) to use the openai backend.")
    base_url = os.environ.get("KODA_LLM_API_BASE") or None
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_seconds)
        response = client.chat.completions.create(model=model, messages=messages, temperature=0)
        text = (response.choices[0].message.content or "").strip()
    except LLMUnavailable:
        raise
    except Exception as exc:  # SDK/transport errors converted to a uniform failure
        raise LLMUnavailable(f"OpenAI request failed: {exc}") from exc
    return LLMResult(text=text, backend="openai", sent_externally=True)
