"""OSV.dev client: match (name, version, ecosystem) tuples against advisories.

This module is one of the two places in the whole scanner allowed to touch the
network (the other is :mod:`scanner.correlate.enrich`). Every network call uses
stdlib :mod:`urllib.request` with an explicit timeout and is wrapped so that a
failure degrades gracefully: :func:`collect` returns an empty result with
``ok=False`` instead of raising.

Flow (see the research notes in ``.research/A2_apis.md``):

1. ``POST /v1/querybatch`` with every concrete ``(name, version, ecosystem)``
   tuple, chunked at <= 1000 queries. The batch response carries only vuln ids.
2. ``GET /v1/vulns/{id}`` for each unique returned id to fetch the full record.
3. Parse each record down to the handful of fields the correlator needs.

Ecosystem strings are passed through exactly as the graph records them
(``PyPI``, ``npm``, ``Packagist``, ``Go``); OSV rejects lowercase variants.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from . import cache

_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/"
_USER_AGENT = "vscan/0.1 (defensive dependency scanner)"
_TIMEOUT = 20.0
# Research verified 1000 is the hard cap; 500 keeps us well under response caps.
_BATCH_CAP = 500

# Vuln records are immutable once published, so a long TTL is safe. Keyed by
# vuln id under a namespace so entries never collide with KEV/EPSS/NVD keys.
_VULN_CACHE_PREFIX = "osv-vuln:"
_VULN_CACHE_TTL = 7 * 24 * 60 * 60  # 7 days, in seconds.
# Bounded pool for the per-id GET /v1/vulns/{id} fetches. Small enough to stay a
# polite client; capped at the number of uncached ids at call time.
_FETCH_WORKERS = 8

# Version strings carrying any of these characters are ranges/constraints, not a
# single concrete version OSV can match -- we skip querying them.
_RANGE_MARKERS = frozenset("<>=~^* ,|!")


class OsvNetworkError(RuntimeError):
    """Raised internally when an OSV request fails; caught by :func:`collect`."""


@dataclass
class DepRef:
    """A dependency to query: mirrors a ``dependency`` graph node."""

    id: str
    name: str
    version: str | None
    ecosystem: str | None


@dataclass
class OsvVuln:
    """A single advisory affecting one dependency, reduced to what we report."""

    id: str
    cve_ids: list[str]
    summary: str
    severity_label: str | None
    cvss_vector: str | None
    fixed_versions: list[str] = field(default_factory=list)
    # The full OSV ``details`` description (markdown), whitespace-collapsed and
    # bounded to _DETAILS_LIMIT. Unlike the one-line ``summary`` (CVE title), the
    # details text usually names the vulnerable function/sink (e.g. "yaml.load",
    # "Session.resolve_redirects"), which symbol-level triage reasons over.
    details: str | None = None


@dataclass
class OsvResult:
    """Outcome of :func:`collect`: advisories per dependency id, plus a flag."""

    by_dep: dict[str, list[OsvVuln]]
    ok: bool
    # Human-readable labels for deps we could not query (no exact version or no
    # ecosystem). Surfaced as a notice so a skip never looks like a clean result.
    skipped: list[str] = field(default_factory=list)


# -- networking ---------------------------------------------------------------


def _post_json(url: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST a JSON body and return the decoded response. Raises OsvNetworkError."""
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, TimeoutError, ValueError, OSError) as exc:
        raise OsvNetworkError(f"OSV POST {url} failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise OsvNetworkError(
            f"OSV POST {url} returned non-object JSON ({type(payload).__name__})"
        )
    return payload


def _get_json(url: str) -> dict[str, Any]:
    """GET a JSON document and return it decoded. Raises OsvNetworkError."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, TimeoutError, ValueError, OSError) as exc:
        raise OsvNetworkError(f"OSV GET {url} failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise OsvNetworkError(
            f"OSV GET {url} returned non-object JSON ({type(payload).__name__})"
        )
    return payload


def query_batch(queries: list[dict[str, Any]]) -> list[list[str]]:
    """Resolve each query to a list of vuln ids via ``POST /v1/querybatch``.

    The returned list is aligned 1:1 with ``queries`` (OSV guarantees order). A
    package with no advisories yields an empty slot ``{}`` which maps to ``[]``.
    Chunked at :data:`_BATCH_CAP`. Pure network boundary -- monkeypatch this in
    tests to avoid hitting OSV.
    """
    results: list[list[str]] = []
    for start in range(0, len(queries), _BATCH_CAP):
        chunk = queries[start : start + _BATCH_CAP]
        payload = _post_json(_QUERYBATCH_URL, {"queries": chunk})
        slots = payload.get("results", [])
        # OSV aligns results 1:1 with the chunk. A short/malformed response would
        # shift every later chunk's ids onto the wrong dependency, so treat a
        # length mismatch as a failed query rather than silently cross-attributing.
        if not isinstance(slots, list) or len(slots) != len(chunk):
            got = len(slots) if isinstance(slots, list) else "non-list"
            raise OsvNetworkError(
                f"OSV querybatch returned {got} results for a {len(chunk)}-query chunk"
            )
        for slot in slots:
            vulns = slot.get("vulns", []) if isinstance(slot, dict) else []
            results.append([v["id"] for v in vulns if isinstance(v, dict) and "id" in v])
    return results


def fetch_vuln(vuln_id: str) -> dict[str, Any]:
    """Fetch the full OSV record for ``vuln_id`` via ``GET /v1/vulns/{id}``.

    Pure network boundary -- monkeypatch this in tests.
    """
    return _get_json(_VULN_URL + vuln_id)


# -- parsing ------------------------------------------------------------------


def _normalize_name(name: str) -> str:
    """Normalize a package name for tolerant matching (PEP503-ish, lowercase)."""
    lowered = name.lower()
    out: list[str] = []
    prev_dash = False
    for ch in lowered:
        if ch in "-_.":
            if not prev_dash:
                out.append("-")
            prev_dash = True
        else:
            out.append(ch)
            prev_dash = False
    return "".join(out).strip("-")


def _cve_ids(record: dict[str, Any]) -> list[str]:
    """Collect CVE ids from the primary id and aliases (uppercased, de-duped)."""
    candidates = [record.get("id", "")] + list(record.get("aliases", []) or [])
    seen: dict[str, None] = {}
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.upper().startswith("CVE-"):
            seen.setdefault(candidate.upper(), None)
    return list(seen)


def _short(text: str | None, limit: int = 300) -> str:
    """Collapse whitespace and truncate a summary/details blob."""
    if not text:
        return ""
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


# The full OSV ``details`` description is bounded to keep finding/bundle payloads
# sane while still carrying enough prose to name the vulnerable function/sink.
_DETAILS_LIMIT = 2000


def _pick_cvss_vector(record: dict[str, Any]) -> str | None:
    """Pick a CVSS vector string from ``severity[]`` (prefer V4, then V3)."""
    severities = record.get("severity") or []
    by_type: dict[str, str] = {}
    for entry in severities:
        if isinstance(entry, dict) and entry.get("score"):
            by_type[str(entry.get("type", ""))] = str(entry["score"])
    for key in ("CVSS_V4", "CVSS_V3", "CVSS_V2"):
        if key in by_type:
            return by_type[key]
    return next(iter(by_type.values()), None)


def _fixed_versions(record: dict[str, Any], name: str, ecosystem: str | None) -> list[str]:
    """Extract ``fixed`` versions for the affected package we actually queried.

    Filters ``affected[]`` to the matching (ecosystem, normalized name) entry
    and reads ``fixed`` events only from ``ECOSYSTEM``/``SEMVER`` ranges. GIT
    ranges carry commit hashes (not versions) and are ignored. When nothing
    matches the queried package, returns ``[]`` rather than leaking fixes from
    unrelated packages.
    """
    target = _normalize_name(name)
    fixed: list[str] = []

    def _collect(entry: dict[str, Any]) -> None:
        for rng in entry.get("ranges", []) or []:
            if not isinstance(rng, dict):
                continue
            # Only version ranges carry usable fixed versions; GIT ranges carry
            # commit hashes we must never surface as a "fixed in" version.
            if str(rng.get("type", "")) not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in rng.get("events", []) or []:
                if not isinstance(event, dict):
                    continue
                value = event.get("fixed")
                if value and value not in fixed:
                    fixed.append(value)

    for entry in record.get("affected", []) or []:
        pkg = entry.get("package", {}) if isinstance(entry, dict) else {}
        eco_ok = ecosystem is None or str(pkg.get("ecosystem", "")) == ecosystem
        name_ok = _normalize_name(str(pkg.get("name", ""))) == target
        if eco_ok and name_ok:
            _collect(entry)
    return fixed


def _merge_group(group: list[OsvVuln]) -> OsvVuln:
    """Collapse advisories that describe the same flaw into one record.

    The GHSA record (which carries the severity label) is preferred as the
    representative for id/summary; CVE ids and fixed versions are unioned.
    """
    representative = next((v for v in group if v.severity_label), group[0])
    cve_ids = sorted({cve for v in group for cve in v.cve_ids})
    fixed: list[str] = []
    for vuln in group:
        for value in vuln.fixed_versions:
            if value not in fixed:
                fixed.append(value)
    return OsvVuln(
        id=representative.id,
        cve_ids=cve_ids,
        summary=representative.summary or next((v.summary for v in group if v.summary), ""),
        severity_label=next((v.severity_label for v in group if v.severity_label), None),
        cvss_vector=next((v.cvss_vector for v in group if v.cvss_vector), None),
        fixed_versions=fixed,
        details=representative.details or next((v.details for v in group if v.details), None),
    )


def merge_vulns(vulns: list[OsvVuln]) -> list[OsvVuln]:
    """Deduplicate advisories that share a CVE alias (GHSA + PYSEC + CVE).

    Uses union-find over CVE ids so transitively-linked records collapse into a
    single :class:`OsvVuln`. Advisories with no CVE id stay distinct.
    """
    parent: dict[Any, Any] = {}

    def find(key: Any) -> Any:
        parent.setdefault(key, key)
        root = key
        while parent[root] != root:
            parent[root] = parent[parent[root]]
            root = parent[root]
        return root

    def union(a: Any, b: Any) -> None:
        parent[find(a)] = find(b)

    keys: list[Any] = []
    for index, vuln in enumerate(vulns):
        if vuln.cve_ids:
            base = ("cve", vuln.cve_ids[0])
            for cve in vuln.cve_ids:
                union(base, ("cve", cve))
            keys.append(base)
        else:
            key = ("id", vuln.id, index)
            find(key)
            keys.append(key)

    groups: dict[Any, list[OsvVuln]] = {}
    # ``keys`` is built one-per-vuln in the loop above (an append in every
    # branch), so the two are guaranteed equal length.
    for vuln, key in zip(vulns, keys, strict=True):
        groups.setdefault(find(key), []).append(vuln)

    merged = [_merge_group(group) for group in groups.values()]
    merged.sort(key=lambda v: v.id)
    return merged


def parse_vuln(record: dict[str, Any], name: str, ecosystem: str | None) -> OsvVuln | None:
    """Reduce a full OSV record to an :class:`OsvVuln`; ``None`` if withdrawn."""
    if record.get("withdrawn"):
        return None
    database_specific = record.get("database_specific") or {}
    summary = record.get("summary") or _short(record.get("details"))
    # The full description, kept alongside the short title: it is the text that
    # usually names the vulnerable function/sink for symbol-level triage.
    details = _short(record.get("details"), limit=_DETAILS_LIMIT) or None
    return OsvVuln(
        id=str(record.get("id", "")),
        cve_ids=_cve_ids(record),
        summary=_short(summary),
        severity_label=database_specific.get("severity"),
        cvss_vector=_pick_cvss_vector(record),
        fixed_versions=_fixed_versions(record, name, ecosystem),
        details=details,
    )


# -- orchestration ------------------------------------------------------------


def _query_version(dep: DepRef) -> str:
    """The version string to send to OSV (Go accepts the leading ``v``)."""
    return str(dep.version)


def is_concrete_version(version: str | None) -> bool:
    """True when ``version`` is a single pinned version OSV can match exactly."""
    if not version:
        return False
    return not any(ch in _RANGE_MARKERS for ch in version)


def _fetch_records(unique_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Return ``{vuln_id: record}`` for every id, cache-first and concurrently.

    Cache hits (7-day TTL, keyed ``osv-vuln:<id>``) never touch the network.
    Remaining ids are fetched in parallel through a bounded thread pool using
    :func:`fetch_vuln` -- the single, monkeypatchable network seam. Only the GETs
    run in threads; cache reads and writes stay on the calling thread.

    Caching is write-through for *successful, non-empty* records only; an error
    or empty payload is never cached. Any fetch failure -- an
    :class:`OsvNetworkError` or any unexpected worker exception -- is surfaced as
    an :class:`OsvNetworkError` so :func:`collect` degrades to ``ok=False``
    exactly as the old sequential path did; nothing escapes as another type.
    """
    records: dict[str, dict[str, Any]] = {}
    to_fetch: list[str] = []
    for vid in unique_ids:
        cached = cache.get(_VULN_CACHE_PREFIX + vid)
        if cached:
            records[vid] = cached
        else:
            to_fetch.append(vid)

    if not to_fetch:
        return records

    fetched: dict[str, dict[str, Any]] = {}
    workers = min(_FETCH_WORKERS, len(to_fetch))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(fetch_vuln, vid): vid for vid in to_fetch}
        for future in as_completed(futures):
            vid = futures[future]
            try:
                fetched[vid] = future.result()
            except OsvNetworkError:
                # Same degradation as before: let collect() catch it.
                raise
            except Exception as exc:  # defensive: never leak a new exception type
                raise OsvNetworkError(
                    f"OSV fetch of {vid} failed in worker: {exc}"
                ) from exc

    # Single-threaded assembly: fold fetched records in and write through to the
    # cache (successful, non-empty payloads only).
    for vid, record in fetched.items():
        records[vid] = record
        if record:
            cache.set(_VULN_CACHE_PREFIX + vid, record, ttl=_VULN_CACHE_TTL)
    return records


def collect(deps: list[DepRef]) -> OsvResult:
    """Match ``deps`` against OSV and return advisories grouped by dependency id.

    Deps whose version is not a single concrete pin are skipped (OSV queries are
    per exact version). Any network failure returns ``OsvResult({}, ok=False)``.
    """
    queries: list[dict[str, Any]] = []
    refs: list[DepRef] = []
    skipped: list[str] = []
    for dep in deps:
        if not dep.ecosystem or not is_concrete_version(dep.version):
            label = f"{dep.name} {dep.version}" if dep.version else f"{dep.name} (no version)"
            skipped.append(label)
            continue
        queries.append(
            {
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                "version": _query_version(dep),
            }
        )
        refs.append(dep)

    if not queries:
        return OsvResult(by_dep={}, ok=True, skipped=skipped)

    try:
        id_lists = query_batch(queries)
        unique_ids: list[str] = []
        seen: set[str] = set()
        for ids in id_lists:
            for vid in ids:
                if vid not in seen:
                    seen.add(vid)
                    unique_ids.append(vid)
        records = _fetch_records(unique_ids)
    except OsvNetworkError:
        return OsvResult(by_dep={}, ok=False, skipped=skipped)

    by_dep: dict[str, list[OsvVuln]] = {}
    # ``refs`` and ``queries`` are appended together, and ``query_batch`` aligns
    # ``id_lists`` 1:1 with ``queries`` (raising on any mismatch), so ``refs`` and
    # ``id_lists`` are guaranteed equal length.
    for ref, ids in zip(refs, id_lists, strict=True):
        vulns: list[OsvVuln] = []
        for vid in ids:
            record = records.get(vid)
            if not record:
                continue
            parsed = parse_vuln(record, ref.name, ref.ecosystem)
            if parsed is not None:
                vulns.append(parsed)
        if vulns:
            by_dep[ref.id] = merge_vulns(vulns)
    return OsvResult(by_dep=by_dep, ok=True, skipped=skipped)
