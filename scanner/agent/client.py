"""OpenAI-compatible chat-completions client (advisory tier only).

This is the only part of the agent layer that performs network I/O, and it is
deliberately provider-neutral: the endpoint, credentials and model are read
entirely from the environment (``LLM_BASE_URL``, ``LLM_API_KEY``,
``LLM_MODEL``) so no provider is ever hardcoded. Only the Python standard
library is used (``urllib``/``json``) -- the agent layer adds no runtime
dependency.

Design contract
---------------
The client never raises into the scanner pipeline. Every failure mode --
missing configuration, connection error, timeout, non-2xx status, malformed
body, truncated JSON -- is turned into a ``None`` return so callers can fall
back to the deterministic offline heuristic. :meth:`LLMClient.available`
reports whether the client is even configured, so a caller can skip the network
entirely when it is not.

The client is purely a text-in/JSON-out transport. It has no access to the
knowledge graph and cannot add or modify edges or reachability verdicts; its
output is consumed only by the advisory assessment tier.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass
from typing import Any

# A conservative default token budget. Reasoning-class models may spend part of
# this on hidden tokens, so keep it generous (research A2 suggests >= 2048).
_DEFAULT_MAX_TOKENS = 2048


@dataclass
class LLMResult:
    """A parsed JSON object plus the raw text the model returned.

    ``data`` is ``None`` when the response could not be parsed into a JSON
    object; ``raw`` is kept for logging/debugging (never the API key).
    """

    data: dict[str, Any] | None
    raw: str | None


class LLMClient:
    """Minimal OpenAI-compatible chat-completions client over stdlib ``urllib``.

    Parameters default to the ``LLM_BASE_URL`` / ``LLM_API_KEY`` / ``LLM_MODEL``
    environment variables. A trailing slash on the base URL is stripped and the
    request is issued to ``{base}/chat/completions``.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        *,
        timeout: float = 60.0,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
    ) -> None:
        raw_base = os.environ.get("LLM_BASE_URL") if base_url is None else base_url
        self.base_url = (raw_base or "").strip().rstrip("/")
        self.api_key = (
            os.environ.get("LLM_API_KEY") if api_key is None else api_key
        ) or ""
        self.model = (os.environ.get("LLM_MODEL") if model is None else model) or ""
        self.timeout = timeout
        self.max_tokens = max_tokens

        # The API key is sent as a Bearer header; over plaintext http:// it would
        # travel in the clear. Warn (don't block -- a local dev proxy is valid).
        if self.base_url.lower().startswith("http://"):
            warnings.warn(
                "LLM_BASE_URL uses plaintext http://; the API key is sent in "
                "the clear. Prefer https:// unless this is a trusted local proxy.",
                stacklevel=2,
            )

    @classmethod
    def disabled(cls) -> "LLMClient":
        """Return a client that is never :meth:`available` (forces offline path)."""
        return cls(base_url="", api_key="", model="")

    # -- configuration --------------------------------------------------------

    def available(self) -> bool:
        """True only when base URL, API key and model are all configured."""
        return bool(self.base_url and self.api_key and self.model)

    # -- request --------------------------------------------------------------

    def complete_json(
        self, system_prompt: str, user_prompt: str
    ) -> dict[str, Any] | None:
        """Request a single JSON object from the model, or ``None`` on any error.

        Tries JSON mode first; on an HTTP 400 (a server rejecting
        ``response_format``/``temperature``) it retries once in plain mode and
        extracts the first JSON object from the text. Never raises.
        """
        if not self.available():
            return None

        result = self._post(system_prompt, user_prompt, json_mode=True)
        if result is not None and result.data is not None:
            return result.data

        # Retry once without response_format/temperature (400-tolerant path).
        result = self._post(system_prompt, user_prompt, json_mode=False)
        if result is not None and result.data is not None:
            return result.data
        return None

    # -- internals ------------------------------------------------------------

    def _post(
        self, system_prompt: str, user_prompt: str, *, json_mode: bool
    ) -> LLMResult | None:
        """Issue one POST; return a parsed result, or ``None`` on transport error."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.max_tokens,
        }
        if json_mode:
            # JSON mode: deterministic + strict JSON. Dropped on the retry so a
            # server that rejects either param can still answer.
            payload["temperature"] = 0
            payload["response_format"] = {"type": "json_object"}

        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "vulnreach-agent/0.1",
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                text = response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and json_mode:
                # Signal the caller to retry in plain mode.
                return LLMResult(data=None, raw=None)
            return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None

        content = self._extract_content(text)
        if content is None:
            return LLMResult(data=None, raw=text)
        parsed = self._parse_json_object(content)
        return LLMResult(data=parsed, raw=content)

    @staticmethod
    def _extract_content(text: str) -> str | None:
        """Pull ``choices[0].message.content`` out of a completions response."""
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        choices = doc.get("choices")
        if not isinstance(choices, list) or not choices:
            return None
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if not isinstance(message, dict):
            return None
        content = message.get("content")
        return content if isinstance(content, str) else None

    @staticmethod
    def _parse_json_object(content: str) -> dict[str, Any] | None:
        """Parse a JSON object from model output, tolerating code fences/prose."""
        stripped = LLMClient._strip_fences(content).strip()
        try:
            doc = json.loads(stripped)
            return doc if isinstance(doc, dict) else None
        except (json.JSONDecodeError, ValueError):
            pass
        # Fall back to the first balanced {...} block in the text.
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start != -1 and end > start:
            try:
                doc = json.loads(stripped[start : end + 1])
                return doc if isinstance(doc, dict) else None
            except (json.JSONDecodeError, ValueError):
                return None
        return None

    @staticmethod
    def _strip_fences(text: str) -> str:
        """Remove a surrounding ```json ... ``` (or plain ```) fence if present."""
        stripped = text.strip()
        if not stripped.startswith("```"):
            return stripped
        lines = stripped.splitlines()
        # Drop the opening fence line (``` or ```json) and a trailing fence.
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines)
