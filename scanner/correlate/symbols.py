"""Shared free-text symbol <-> advisory matching engine (pure, offline).

This is the single, deterministic implementation of two questions asked about a
CVE/advisory description:

* which specific function/feature names does the advisory prose name? and
* is any symbol the project actually calls the advisory's named sink?

Both answers are extracted with whole-word, case-insensitive token matching over
the raw advisory text -- no API key, no model, no network. The logic lives here
(rather than in :mod:`scanner.agent.triage`, its first consumer) so the
correlator's deterministic ``symbol_match`` signal and the advisory triage tier
reason over exactly the same extractor.

Import direction: this module imports NOTHING from :mod:`scanner.agent` (and so
cannot create a cycle); :mod:`scanner.agent` imports *from* here.
"""

from __future__ import annotations

import re

# Generic trailing identifiers that, on their own, are too weak to treat as a
# vulnerable-symbol match (they appear constantly in English/CVE prose). A bare
# last component in this set never fires the AFFECTED trigger; the full dotted
# symbol (e.g. "yaml.load") still does. The generous matcher (used only to
# WITHHOLD a "safe" verdict) ignores this set, staying conservative.
_GENERIC_TOKENS = frozenset(
    {
        "get", "set", "put", "post", "open", "read", "write", "load", "dump",
        "run", "call", "make", "use", "add", "new", "init", "close", "send",
        "list", "copy", "parse", "data", "value", "object", "request",
        "response", "handler", "main", "start", "stop", "update",
    }
)

# A "specific named function/feature" in CVE prose: a dotted path whose final
# component is a real identifier (>=3 chars) -- e.g. ``yaml.full_load``,
# ``PIL.Image.open``, ``Session.resolve_redirects`` -- or a bare ``name()``
# call form. Version strings like ``1.24.2`` never match (they do not start with
# a letter), and abbreviations like ``e.g`` fail the >=3-char final-component
# rule, so they are not mistaken for a named function.
_NAMED_FUNC_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b"  # dotted path
    r"|\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\(\))"  # bare name() form
)


def _symbol_tokens(symbol: str, *, strict: bool) -> set[str]:
    """Candidate text tokens that represent ``symbol`` in CVE prose.

    Always includes the full dotted symbol (``yaml.load``) and its last two
    components (``Image.open``). The bare final component (``load``, ``open``) is
    included only in the GENEROUS mode, because on its own it is too generic to
    be a reliable AFFECTED trigger -- but it is a fine reason to WITHHOLD a
    "safe" verdict (the conservative direction).
    """
    parts = symbol.split(".")
    tokens: set[str] = {symbol.lower()}
    if len(parts) >= 2:
        tokens.add(".".join(parts[-2:]).lower())
    last = parts[-1].lower()
    if strict:
        if last not in _GENERIC_TOKENS and len(last) >= 4:
            tokens.add(last)
    else:
        if last:
            tokens.add(last)
    return tokens


def _token_in_text(token: str, lower_text: str) -> bool:
    """Whole-word (``\\b``-anchored) case-insensitive presence test."""
    return re.search(r"\b" + re.escape(token) + r"\b", lower_text) is not None


def _match_called_symbol(
    called_symbols: list[str], lower_text: str, *, strict: bool
) -> tuple[str, str] | None:
    """First ``(symbol, matched_token)`` whose token occurs in ``lower_text``.

    Longer tokens are tried first so the most specific match (the full dotted
    symbol) is preferred and cited.
    """
    for symbol in called_symbols:
        for token in sorted(_symbol_tokens(symbol, strict=strict), key=len, reverse=True):
            if _token_in_text(token, lower_text):
                return symbol, token
    return None


def _named_functions(text: str) -> list[str]:
    """Specific function/feature tokens named in the CVE text (dotted or ``()``)."""
    out: list[str] = []
    for match in _NAMED_FUNC_RE.finditer(text):
        token = match.group(0)
        if "." in token:
            if len(token.split(".")[-1]) >= 3:
                out.append(token)
        else:
            out.append(token)
    return out


# -- public API (consumed by the correlator and the advisory triage tier) -----


def advisory_matches_called_symbol(called_symbols: list[str], text: str) -> bool:
    """Whether any ``called_symbols`` entry is the advisory's named sink.

    Uses the STRICT token set (the full dotted symbol, its last two components,
    and a non-generic >=4-char final component) so this positive claim -- "the
    vulnerable function is actually called" -- stays conservative and never
    fires on a generic word shared with the prose.
    """
    return _match_called_symbol(called_symbols, text.lower(), strict=True) is not None
