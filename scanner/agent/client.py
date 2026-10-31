"""OpenAI-compatible chat-completions client (advisory tier only).

This is the only part of the agent layer that performs network I/O, and it is
deliberately provider-neutral: the endpoint, credentials and model are read
entirely from the environment (``LLM_BASE_URL``, ``LLM_API_KEY``,
``LLM_MODEL``) so no provider is ever hardcoded. Only the Python standard
library is used (``urllib``/``json``/``time``/``random``) -- the agent layer
adds no runtime dependency.

Design contract
---------------
The client never raises into the scanner pipeline. Every failure mode --
missing configuration, connection error, timeout, non-2xx status, malformed
body, truncated JSON -- is turned into a ``None`` return so callers can fall
back to the deterministic offline heuristic. :meth:`LLMClient.available`
reports whether the client is even configured, so a caller can skip the network
entirely when it is not.

Transient endpoint failures are tolerated: the request is retried, with short
exponential backoff and jitter, on HTTP 429/>=500/404 and on connection-level
errors (the configured endpoint intermittently flaps ``model_not_found`` as a
404 for a model that is in fact valid, and recovers on retry). After the retry
budget is exhausted the client still returns ``None`` rather than raising.

The client is purely a text-in/JSON-out transport. It has no access to the
knowledge graph and cannot add or modify edges or reachability verdicts; its
output is consumed only by the advisory assessment tier.
"""

from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass
from typing import Any

# A generous default token budget. The configured model may be a reasoning-class
# model that spends a large, variable share of the budget on hidden reasoning
# tokens before emitting the structured answer; too small a budget truncates the
# answer to empty. Overridable via the ``max_tokens`` argument or the
# ``LLM_MAX_TOKENS`` environment variable.
_DEFAULT_MAX_TOKENS = 4096

# Bounded transient-retry policy. At most ``_MAX_ATTEMPTS`` HTTP attempts per
# request shape, with exponential backoff (~0.5s, ~1s) plus a little jitter.
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 0.5
_BACKOFF_JITTER_SECONDS = 0.1

# Sentinel the chat transport returns when the endpoint rejects the request
# *shape* with HTTP 400 (e.g. an unsupported ``temperature`` field alongside
# ``tools``). It is not transient: the caller retries once with a more
# conservative payload (no ``temperature``) before degrading to ``None``.
_HTTP_400 = object()


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
        max_tokens: int | None = None,
    ) -> None:
        raw_base = os.environ.get("LLM_BASE_URL") if base_url is None else base_url
        self.base_url = (raw_base or "").strip().rstrip("/")
        self.api_key = (
            os.environ.get("LLM_API_KEY") if api_key is None else api_key
        ) or ""
        self.model = (os.environ.get("LLM_MODEL") if model is None else model) or ""
        self.timeout = timeout
        self.max_tokens = (
            max_tokens if max_tokens is not None else self._env_max_tokens()
        )

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

    @staticmethod
    def _env_max_tokens() -> int:
        """Resolve the token budget from ``LLM_MAX_TOKENS`` or the default."""
        raw = os.environ.get("LLM_MAX_TOKENS")
        if raw:
            try:
                value = int(raw)
            except ValueError:
                return _DEFAULT_MAX_TOKENS
            if value > 0:
                return value
        return _DEFAULT_MAX_TOKENS

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
        extracts the first JSON object from the text. Each attempt is itself
        retried on transient failures (see :meth:`_post`). Never raises.
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

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        tool_choice: str = "auto",
    ) -> dict[str, Any] | None:
        """Run one tool-calling chat turn, or return ``None`` on any error.

        ``messages`` is a full OpenAI-style message list (``system`` / ``user``
        / ``assistant`` / ``tool`` roles, including assistant turns that carry
        ``tool_calls`` and the ``tool`` results answering them). ``tools`` is a
        list of OpenAI function schemas the model may call this turn, or ``None``
        / ``[]`` to disable tool use (used for the final, tools-off answer).

        On success returns ``{"content": str | None, "tool_calls": list,
        "raw": dict}`` where ``raw`` is the model's message object exactly as the
        API returned it (so the caller can append it verbatim and keep the
        tool-call ids intact) and ``tool_calls`` is that message's
        ``tool_calls`` list (empty when the model gave a final answer).

        Provider-neutral and never raises: a missing configuration, transport
        flake, non-2xx status, or unparsable body all collapse to ``None`` so
        the caller can degrade gracefully. Mirrors :meth:`complete_json`: a
        first attempt pins ``temperature=0`` for determinism and, on an HTTP 400
        rejecting that shape, retries once without it.
        """
        if not self.available():
            return None

        result = self._post_chat(messages, tools, tool_choice, with_temperature=True)
        if result is _HTTP_400:
            # Not transient: the server rejected the request shape. Retry once
            # with the more conservative payload (drop ``temperature``).
            result = self._post_chat(
                messages, tools, tool_choice, with_temperature=False
            )
        return None if (result is None or result is _HTTP_400) else result

    # -- internals ------------------------------------------------------------

    def _post(
        self, system_prompt: str, user_prompt: str, *, json_mode: bool
    ) -> LLMResult | None:
        """Issue a POST with bounded transient retry; return a parsed result.

        Returns ``None`` on a non-retryable transport error or after the retry
        budget is exhausted. A 400 in JSON mode is *not* transient: it returns a
        sentinel ``LLMResult(data=None, raw=None)`` so :meth:`complete_json` can
        retry once in plain mode. Transient failures -- HTTP 429, HTTP >= 500,
        HTTP 404 (this endpoint flaps ``model_not_found`` for a valid model),
        and ``URLError``/``TimeoutError``/``OSError`` -- are retried up to
        ``_MAX_ATTEMPTS`` times with short exponential backoff plus jitter.
        """
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
            "User-Agent": "vscan-agent/0.1",
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )

        text: str | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout
                ) as response:
                    charset = response.headers.get_content_charset() or "utf-8"
                    text = response.read().decode(charset, errors="replace")
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 400 and json_mode:
                    # Not transient: signal the caller to retry in plain mode.
                    return LLMResult(data=None, raw=None)
                if self._is_transient_status(exc.code) and self._has_retry_left(
                    attempt
                ):
                    self._backoff(attempt)
                    continue
                return None
            except (urllib.error.URLError, TimeoutError, OSError):
                # Connection-level flake (HTTPError handled above): retry.
                if self._has_retry_left(attempt):
                    self._backoff(attempt)
                    continue
                return None
            except ValueError:
                # Malformed URL / request shape -- not transient.
                return None

        if text is None:
            return None

        content = self._extract_content(text)
        if content is None:
            return LLMResult(data=None, raw=text)
        parsed = self._parse_json_object(content)
        return LLMResult(data=parsed, raw=content)

    def _post_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        tool_choice: str,
        *,
        with_temperature: bool,
    ) -> dict[str, Any] | None | object:
        """POST a tool-calling chat turn with bounded transient retry.

        Returns the model's parsed message dict (``{content, tool_calls, raw}``)
        on success, :data:`_HTTP_400` if the endpoint rejects the request shape
        (so :meth:`chat` can retry without ``temperature``), or ``None`` on a
        non-retryable transport error or once the retry budget is spent. The
        retry policy matches :meth:`_post`: HTTP 429/>=500/404 and
        connection-level flakes are retried with exponential backoff + jitter.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        if with_temperature:
            payload["temperature"] = 0

        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "vscan-agent/0.1",
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )

        text: str | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout
                ) as response:
                    charset = response.headers.get_content_charset() or "utf-8"
                    text = response.read().decode(charset, errors="replace")
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 400 and with_temperature:
                    # Not transient: signal the caller to retry a leaner shape.
                    return _HTTP_400
                if self._is_transient_status(exc.code) and self._has_retry_left(
                    attempt
                ):
                    self._backoff(attempt)
                    continue
                return None
            except (urllib.error.URLError, TimeoutError, OSError):
                if self._has_retry_left(attempt):
                    self._backoff(attempt)
                    continue
                return None
            except ValueError:
                return None

        if text is None:
            return None
        return self._extract_message(text)

    @staticmethod
    def _extract_message(text: str) -> dict[str, Any] | None:
        """Pull ``choices[0].message`` out and shape it for :meth:`chat`.

        Returns ``{"content": str | None, "tool_calls": list, "raw": <message>}``
        or ``None`` when the body is not a well-formed completions response.
        """
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        choices = doc.get("choices") if isinstance(doc, dict) else None
        if not isinstance(choices, list) or not choices:
            return None
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if not isinstance(message, dict):
            return None
        content = message.get("content")
        tool_calls = message.get("tool_calls")
        return {
            "content": content if isinstance(content, str) else None,
            "tool_calls": tool_calls if isinstance(tool_calls, list) else [],
            "raw": message,
        }

    @staticmethod
    def _is_transient_status(code: int) -> bool:
        """Whether an HTTP status is worth retrying on this endpoint.

        404 is treated as transient because the endpoint intermittently returns
        ``model_not_found`` for a model that is valid and recovers on retry.
        """
        return code == 404 or code == 429 or code >= 500

    @staticmethod
    def _has_retry_left(attempt: int) -> bool:
        return attempt + 1 < _MAX_ATTEMPTS

    @staticmethod
    def _backoff(attempt: int) -> None:
        """Sleep with exponential backoff (~0.5s, ~1s) plus a little jitter."""
        delay = _BACKOFF_BASE_SECONDS * (2**attempt)
        delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
        time.sleep(delay)

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
