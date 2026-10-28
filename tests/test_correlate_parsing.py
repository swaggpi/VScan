"""Direct unit tests for the NVD / EPSS / KEV response parsing in
``scanner.correlate.enrich``.

The existing ``test_correlate.py`` mocks the whole enrichment boundary
(``fetch_kev_catalog`` / ``query_epss``), so the real JSON-parsing code never
runs there. These tests feed canned JSON blobs -- shaped exactly like the real
NVD 2.0 / EPSS v1 / CISA KEV responses -- straight through the parsers,
stubbing ONLY the lowest HTTP primitive (``enrich._get``) and never the parse
functions themselves, with exact-value assertions.
"""

from __future__ import annotations

import json

import pytest

from scanner.correlate import enrich


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Redirect the on-disk cache so fetch_* helpers never touch the real one."""
    monkeypatch.setenv("VSCAN_CACHE_DIR", str(tmp_path / "vscan-cache"))


def _stub_get(monkeypatch, payload):
    """Stub the single HTTP primitive to return ``payload`` as JSON bytes."""
    body = json.dumps(payload).encode("utf-8")
    monkeypatch.setattr(enrich, "_get", lambda url, headers=None: body)


# -- _parse_nvd: metric selection --------------------------------------------


def _nvd_payload(metrics: dict) -> dict:
    return {"vulnerabilities": [{"cve": {"metrics": metrics}}]}


def test_parse_nvd_prefers_v40_over_all_lower_versions():
    payload = _nvd_payload(
        {
            "cvssMetricV40": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.3,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",
                    },
                }
            ],
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    },
                }
            ],
        }
    )
    assert enrich._parse_nvd(payload) == (9.3, "CRITICAL", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N")


def test_parse_nvd_prefers_v31_over_v30():
    payload = _nvd_payload(
        {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N",
                    },
                }
            ],
            "cvssMetricV30": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 6.0,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.0/AV:N",
                    },
                }
            ],
        }
    )
    assert enrich._parse_nvd(payload) == (8.1, "HIGH", "CVSS:3.1/AV:N")


def test_parse_nvd_prefers_v30_over_v2():
    payload = _nvd_payload(
        {
            "cvssMetricV30": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 5.5,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.0/AV:L",
                    },
                }
            ],
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "baseSeverity": "HIGH",
                    "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                }
            ],
        }
    )
    assert enrich._parse_nvd(payload) == (5.5, "MEDIUM", "CVSS:3.0/AV:L")


def test_parse_nvd_v2_reads_sibling_base_severity():
    # V2 carries ``baseSeverity`` as a sibling of ``cvssData``, not inside it.
    payload = _nvd_payload(
        {
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "baseSeverity": "HIGH",
                    "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                }
            ]
        }
    )
    assert enrich._parse_nvd(payload) == (7.5, "HIGH", "AV:N/AC:L/Au:N/C:P/I:P/A:P")


def test_parse_nvd_selects_primary_over_secondary():
    payload = _nvd_payload(
        {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "baseScore": 5.0,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.1/SECONDARY",
                    },
                },
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/PRIMARY",
                    },
                },
            ]
        }
    )
    # Primary wins even though it is listed second.
    assert enrich._parse_nvd(payload) == (9.8, "CRITICAL", "CVSS:3.1/PRIMARY")


def test_parse_nvd_falls_back_to_first_when_no_primary():
    payload = _nvd_payload(
        {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "baseScore": 4.2,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.1/FIRST",
                    },
                },
                {
                    "type": "Secondary",
                    "cvssData": {
                        "baseScore": 8.8,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/SECOND",
                    },
                },
            ]
        }
    )
    assert enrich._parse_nvd(payload) == (4.2, "MEDIUM", "CVSS:3.1/FIRST")


def test_parse_nvd_no_metrics_returns_empty():
    assert enrich._parse_nvd(_nvd_payload({})) == (None, None, None)


def test_parse_nvd_no_vulnerabilities_returns_empty():
    assert enrich._parse_nvd({"vulnerabilities": []}) == (None, None, None)
    assert enrich._parse_nvd({}) == (None, None, None)


def test_parse_nvd_non_numeric_score_is_none():
    payload = _nvd_payload(
        {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": "oops",
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N",
                    },
                }
            ]
        }
    )
    assert enrich._parse_nvd(payload) == (None, "HIGH", "CVSS:3.1/AV:N")


def test_fetch_nvd_cvss_parses_stubbed_response(monkeypatch):
    payload = _nvd_payload(
        {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        }
    )
    _stub_get(monkeypatch, payload)
    assert enrich.fetch_nvd_cvss("CVE-2020-1747", api_key=None) == (
        9.8,
        "CRITICAL",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )


# -- EPSS ---------------------------------------------------------------------


def test_query_epss_parses_response_into_scores(monkeypatch):
    _stub_get(
        monkeypatch,
        {
            "status": "OK",
            "data": [
                {"cve": "CVE-2020-1747", "epss": "0.97", "percentile": "0.995"},
                {"cve": "CVE-2019-10744", "epss": "0.12345", "percentile": "0.5"},
            ],
        },
    )
    result = enrich.query_epss(["CVE-2020-1747", "CVE-2019-10744"])
    assert result == {
        "CVE-2020-1747": (0.97, 0.995),
        "CVE-2019-10744": (0.12345, 0.5),
    }


def test_epss_chunks_empty():
    assert enrich._epss_chunks([]) == []


def test_epss_chunks_batches_by_id_count():
    # 250 short ids -> chunks capped at _EPSS_MAX_IDS (100): [100, 100, 50].
    ids = [f"CVE-2021-{i:05d}" for i in range(250)]
    chunks = enrich._epss_chunks(ids)
    assert [len(c) for c in chunks] == [100, 100, 50]
    # No id dropped or duplicated across the chunk boundaries.
    assert [cve for chunk in chunks for cve in chunk] == ids


def test_epss_chunks_batches_by_request_length():
    # 100-char ids: the running length (first id + 101 per subsequent) crosses
    # the ~1900-char cap after exactly 18 ids, before the 100-id count cap.
    ids = ["A" * 100 for _ in range(20)]
    chunks = enrich._epss_chunks(ids)
    assert [len(c) for c in chunks] == [18, 2]
    # Every chunk's joined ``cve=`` value stays within the char budget.
    for chunk in chunks:
        assert len(",".join(chunk)) <= enrich._EPSS_MAX_CHARS


# -- CISA KEV -----------------------------------------------------------------


def test_fetch_kev_catalog_parses_cve_id_set(monkeypatch):
    _stub_get(
        monkeypatch,
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
                {"cveID": "cve-2020-1472", "vendorProject": "Microsoft"},
                {"vendorProject": "NoCveHere"},  # missing cveID -> skipped
            ],
        },
    )
    assert enrich.fetch_kev_catalog() == {"CVE-2021-44228", "CVE-2020-1472"}


# -- _to_float ----------------------------------------------------------------


def test_to_float_valid():
    assert enrich._to_float("0.5") == 0.5
    assert enrich._to_float(7) == 7.0
    assert enrich._to_float(2.5) == 2.5


def test_to_float_invalid_returns_none():
    assert enrich._to_float("not-a-number") is None


def test_to_float_missing_returns_none():
    assert enrich._to_float(None) is None
