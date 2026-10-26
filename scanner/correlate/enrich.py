"""Enrichment: CISA KEV, EPSS and (optional, best-effort) NVD CVSS scores.

Second and last network-touching module. Like :mod:`scanner.correlate.osv`
every call uses stdlib :mod:`urllib.request` with a timeout and the same
graceful-failure contract: a network error sets a notice and leaves findings
un-enriched rather than raising.

* **CISA KEV** -- download the catalog once (cached ~1 day) and expose the set
  of actively-exploited ``cveID`` values.
* **EPSS** -- batch-query CVE ids (chunked by request-length, not count, per the
  ~2000-char limit) for ``epss`` + ``percentile`` (strings cast to float).
* **NVD** -- optional numeric CVSS base score, rate-limited and cached; never
  blocks the core run (opt-in via ``use_nvd``). When skipped the OSV vector and
  severity label carry the severity signal instead.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import cache

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_EPSS_URL = "https://api.first.org/data/v1/epss"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "vulnreach/0.1 (defensive dependency scanner)"
_TIMEOUT = 30.0

_KEV_TTL = 24 * 60 * 60  # ~1 day; catalog updates on business days.
_EPSS_TTL = 12 * 60 * 60
_NVD_TTL = 7 * 24 * 60 * 60

# EPSS: keep each ``cve=`` value well under the ~2000-char limit, and <=100 ids
# so a single page holds the whole chunk (default limit=100).
_EPSS_MAX_CHARS = 1900
_EPSS_MAX_IDS = 100


class EnrichNetworkError(RuntimeError):
    """Raised internally when an enrichment request fails; caught per stage."""


def _get(url: str, headers: dict[str, str] | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            return response.read()
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        raise EnrichNetworkError(f"GET {url} failed: {exc}") from exc


# -- CISA KEV -----------------------------------------------------------------


def fetch_kev_catalog() -> set[str]:
    """Return the set of actively-exploited CVE ids from the CISA KEV catalog.

    Cached on disk for ~1 day. Raises :class:`EnrichNetworkError` on failure.
    Pure network boundary -- monkeypatch this in tests.
    """
    cached = cache.get("kev-catalog")
    if isinstance(cached, list):
        return {str(cve).upper() for cve in cached}

    try:
        payload = json.loads(_get(_KEV_URL).decode("utf-8"))
        if not isinstance(payload, dict):
            raise EnrichNetworkError("KEV catalog was not a JSON object")
        cve_ids = [
            str(entry["cveID"]).upper()
            for entry in payload.get("vulnerabilities", [])
            if isinstance(entry, dict) and entry.get("cveID")
        ]
    except (ValueError, AttributeError, TypeError, KeyError, EnrichNetworkError) as exc:
        raise EnrichNetworkError(f"KEV download failed: {exc}") from exc

    cache.set("kev-catalog", cve_ids, ttl=_KEV_TTL)
    return set(cve_ids)


# -- EPSS ---------------------------------------------------------------------


def _epss_chunks(cve_ids: list[str]) -> list[list[str]]:
    """Split CVE ids into chunks bounded by request length and id count."""
    chunks: list[list[str]] = []
    current: list[str] = []
    length = 0
    for cve in cve_ids:
        extra = len(cve) + (1 if current else 0)
        if current and (length + extra > _EPSS_MAX_CHARS or len(current) >= _EPSS_MAX_IDS):
            chunks.append(current)
            current, length = [], 0
            extra = len(cve)
        current.append(cve)
        length += extra
    if current:
        chunks.append(current)
    return chunks


def query_epss(cve_ids: list[str]) -> dict[str, tuple[float | None, float | None]]:
    """Return ``{cve: (epss, percentile)}`` for scored CVEs (missing -> absent).

    Chunked by request length. Per-CVE results are cached. Raises
    :class:`EnrichNetworkError` on network failure. Pure network boundary --
    monkeypatch this in tests.
    """
    result: dict[str, tuple[float | None, float | None]] = {}
    pending: list[str] = []
    for cve in cve_ids:
        cached = cache.get(f"epss:{cve}")
        if isinstance(cached, list) and len(cached) == 2:
            result[cve] = (cached[0], cached[1])
        else:
            pending.append(cve)

    for chunk in _epss_chunks(pending):
        query = urllib.parse.urlencode({"cve": ",".join(chunk), "limit": _EPSS_MAX_IDS})
        try:
            payload = json.loads(_get(f"{_EPSS_URL}?{query}").decode("utf-8"))
            if not isinstance(payload, dict):
                raise EnrichNetworkError("EPSS response was not a JSON object")
            rows = payload.get("data", []) or []
        except (ValueError, AttributeError, TypeError, KeyError, EnrichNetworkError) as exc:
            raise EnrichNetworkError(f"EPSS decode failed: {exc}") from exc
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).upper()
            epss = _to_float(row.get("epss"))
            percentile = _to_float(row.get("percentile"))
            result[cve] = (epss, percentile)
            cache.set(f"epss:{cve}", [epss, percentile], ttl=_EPSS_TTL)
    return result


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# -- NVD (optional) -----------------------------------------------------------


def fetch_nvd_cvss(cve_id: str, api_key: str | None) -> tuple[float | None, str | None, str | None]:
    """Return ``(base_score, base_severity, vector)`` for ``cve_id`` from NVD.

    Best-effort and rate-limited (5 req/30s without a key, 50 with one), cached
    on disk. Returns ``(None, None, None)`` when unknown. Raises
    :class:`EnrichNetworkError` on network failure. Pure network boundary --
    monkeypatch this in tests.
    """
    cached = cache.get(f"nvd:{cve_id}")
    if isinstance(cached, list) and len(cached) == 3:
        return (cached[0], cached[1], cached[2])

    query = urllib.parse.urlencode({"cveId": cve_id})
    headers = {"apiKey": api_key} if api_key else {}
    try:
        payload = json.loads(_get(f"{_NVD_URL}?{query}", headers=headers).decode("utf-8"))
        if not isinstance(payload, dict):
            raise EnrichNetworkError("NVD response was not a JSON object")
        parsed = _parse_nvd(payload)
    except (ValueError, AttributeError, TypeError, KeyError, EnrichNetworkError) as exc:
        raise EnrichNetworkError(f"NVD decode failed: {exc}") from exc

    cache.set(f"nvd:{cve_id}", list(parsed), ttl=_NVD_TTL)
    return parsed


def _parse_nvd(payload: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Pick the preferred CVSS metric (V4 > V3.1 > V3.0 > V2, Primary first)."""
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return (None, None, None)
    metrics = (vulns[0].get("cve", {}) or {}).get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData", {}) or {}
        score = data.get("baseScore")
        # V3.x nests baseSeverity in cvssData; V2 has it as a sibling.
        severity = data.get("baseSeverity") or chosen.get("baseSeverity")
        return (
            float(score) if isinstance(score, (int, float)) else None,
            str(severity) if severity else None,
            data.get("vectorString"),
        )
    return (None, None, None)


def _nvd_sleep(api_key: str | None) -> None:
    """Polite inter-request delay to respect NVD's rolling-window rate limit."""
    time.sleep(0.6 if api_key else 6.0)


# -- orchestration ------------------------------------------------------------


def enrich_findings(findings: list[Any], *, use_nvd: bool) -> list[str]:
    """Attach KEV / EPSS (and optional NVD CVSS) data to ``findings`` in place.

    Returns a list of human-readable notices describing any stage that could not
    reach the network. Never raises -- enrichment is best-effort.
    """
    notices: list[str] = []
    if not findings:
        return notices

    all_cves = sorted({cve for f in findings for cve in f.cve_ids})

    # CISA KEV.
    try:
        kev = fetch_kev_catalog()
        for finding in findings:
            finding.kev = any(cve in kev for cve in finding.cve_ids)
    except EnrichNetworkError as exc:
        notices.append(f"CISA KEV lookup unavailable ({exc}); exploitation flags omitted.")

    # EPSS.
    try:
        epss = query_epss(all_cves)
        for finding in findings:
            best: tuple[float, float | None] | None = None
            for cve in finding.cve_ids:
                score, percentile = epss.get(cve, (None, None))
                if score is not None and (best is None or score > best[0]):
                    best = (score, percentile)
            if best is not None:
                finding.epss, finding.epss_percentile = best
    except EnrichNetworkError as exc:
        notices.append(f"EPSS lookup unavailable ({exc}); exploit-probability omitted.")

    # NVD numeric CVSS (optional / best-effort).
    if use_nvd:
        notices.extend(_apply_nvd(findings))

    return notices


def _apply_nvd(findings: list[Any]) -> list[str]:
    """Fill numeric CVSS scores from NVD for findings that lack one."""
    api_key = os.environ.get("NVD_API_KEY") or None
    looked_up: dict[str, tuple[float | None, str | None, str | None]] = {}
    first = True
    for finding in findings:
        if finding.cvss_score is not None or not finding.cve_ids:
            continue
        cve = finding.cve_ids[0]
        try:
            if cve not in looked_up:
                if not first:
                    _nvd_sleep(api_key)
                first = False
                looked_up[cve] = fetch_nvd_cvss(cve, api_key)
            score, severity, vector = looked_up[cve]
        except EnrichNetworkError as exc:
            return [f"NVD CVSS lookup stopped ({exc}); OSV severity labels retained."]
        if score is not None:
            finding.cvss_score = score
            finding.cvss_source = "NVD"
            if severity:
                finding.severity = severity
            if vector:
                finding.cvss_vector = vector
    return []
