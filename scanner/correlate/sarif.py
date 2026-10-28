"""SARIF 2.1.0 and markdown renderers for the audit payload.

Both functions are pure, offline, stdlib-only renderers of the dict returned by
:func:`scanner.correlate.report.audit`. They add no scan/reachability/taint
signal and change no verdict -- they only reshape the already-computed findings
into CI- and PR-friendly output:

* :func:`to_sarif`    -- a valid SARIF 2.1.0 log (for code scanning / GitHub).
* :func:`to_markdown` -- a GitHub-comment-ready summary + findings table.

Neither renderer requires the advisory LLM tiers; both are deterministic, so
they are safe to produce offline and their ordering is stable.
"""

from __future__ import annotations

from typing import Any

from ..graph import KnowledgeGraph
from .report import funnel_line

# SARIF 2.1.0 schema + the project's information URI (reported on tool.driver).
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
_INFORMATION_URI = "https://github.com/swaggpi/VScan"

# Repo-relative placeholder when a dependency carries no manifest source file.
_NO_MANIFEST_URI = "dependency-manifest"

# Cap the markdown findings table so a PR comment stays compact.
_MARKDOWN_TABLE_CAP = 25


def _rule_id(finding: dict[str, Any]) -> str:
    """The stable rule id for a finding: its first CVE id, else the vuln id."""
    cve_ids = finding.get("cve_ids") or []
    if cve_ids:
        return cve_ids[0]
    return finding.get("vuln_id") or "UNKNOWN"


def _level(finding: dict[str, Any]) -> str:
    """Map a finding to a SARIF result level.

    ``error``   -- attacker input is PROVEN to reach the call (taint == tainted).
    ``warning`` -- the vulnerable function is confirmed reached, or the package
                   is reachable from a public entry point.
    ``note``    -- neither (e.g. unreachable / potentially reachable only).
    """
    if finding.get("taint") == "tainted":
        return "error"
    if finding.get("symbol_match") == "confirmed" or finding.get("reachable"):
        return "warning"
    return "note"


def _dep_at_version(finding: dict[str, Any]) -> str:
    return f"{finding.get('dependency_name')}@{finding.get('version')}"


def _cve_label(finding: dict[str, Any]) -> str:
    return ", ".join(finding.get("cve_ids") or []) or (finding.get("vuln_id") or "")


def _result_message(finding: dict[str, Any]) -> str:
    """A concise sentence naming dep@version, CVE, verdict, symbol, taint, fix."""
    fixed = finding.get("fixed_versions") or []
    fix_text = f"fixed in {', '.join(fixed)}" if fixed else "no fixed version listed"
    return (
        f"{_dep_at_version(finding)} is affected by {_cve_label(finding)}: "
        f"verdict={finding.get('verdict')}, "
        f"symbol_match={finding.get('symbol_match')}, "
        f"taint={finding.get('taint')}; {fix_text}."
    )


def _manifest_uri(finding: dict[str, Any], graph: KnowledgeGraph) -> str:
    """The dependency's manifest source file, or a repo-relative placeholder."""
    node = graph.get_node(finding.get("dependency_id", ""))
    if node is not None:
        source_file = node.attrs.get("source_file")
        if source_file:
            return source_file
    return _NO_MANIFEST_URI


def to_sarif(payload: dict[str, Any], graph: KnowledgeGraph) -> dict[str, Any]:
    """Render an audit payload as a SARIF 2.1.0 log.

    One ``reportingDescriptor`` rule per unique CVE/vuln id, one ``result`` per
    finding. Rules and results are sorted (by id, then dependency) so the output
    is byte-stable for the same input.
    """
    # Sort once, up front, so BOTH the per-rule representative finding and the
    # results are chosen in a deterministic order -- the output is then
    # byte-stable regardless of the input finding order.
    ordered = sorted(
        payload.get("findings", []),
        key=lambda f: (
            _rule_id(f),
            f.get("dependency_id") or "",
            f.get("vuln_id") or "",
        ),
    )

    # One rule per unique id; the representative is the first finding in the
    # deterministic order (its summary/details describe the advisory).
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in ordered:
        rules_by_id.setdefault(_rule_id(finding), finding)

    rules: list[dict[str, Any]] = []
    for rule_id in sorted(rules_by_id):
        finding = rules_by_id[rule_id]
        rule: dict[str, Any] = {
            "id": rule_id,
            "shortDescription": {"text": finding.get("summary") or rule_id},
        }
        details = finding.get("details")
        if details:
            rule["fullDescription"] = {"text": details}
            rule["help"] = {"text": details}
        cvss = finding.get("cvss_score")
        if cvss is not None:
            # GitHub ranks results by this numeric CVSS string.
            rule["properties"] = {"security-severity": str(cvss)}
        rules.append(rule)

    results: list[dict[str, Any]] = []
    for finding in ordered:
        results.append(
            {
                "ruleId": _rule_id(finding),
                "level": _level(finding),
                "message": {"text": _result_message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _manifest_uri(finding, graph)
                            },
                            # No per-line data exists for a declared dependency.
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    "vscan/v1": (
                        f"{finding.get('dependency_id')}|{finding.get('vuln_id')}"
                    )
                },
                "properties": {
                    "verdict": finding.get("verdict"),
                    "symbol_match": finding.get("symbol_match"),
                    "taint": finding.get("taint"),
                    "example_path": finding.get("example_path") or [],
                },
            }
        )

    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VScan",
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _md_cell(value: Any) -> str:
    """Render a markdown table cell, escaping the pipe delimiter."""
    return str(value).replace("|", "\\|")


def to_markdown(payload: dict[str, Any]) -> str:
    """Render an audit payload as a GitHub-comment-ready markdown string.

    The funnel line leads as a summary; a compact table lists the top reachable/
    exploitable findings (capped, with a note for the remainder). When nothing is
    reachable it emits a clean all-clear message.
    """
    summary = payload.get("summary", {})
    findings = payload.get("findings", [])

    lines: list[str] = ["## vscan audit", ""]
    lines.append(funnel_line(summary))
    lines.append("")

    # Findings are already ranked by the audit payload; highlight the reachable
    # and the proven-exploitable ones -- the signal a reviewer acts on.
    highlighted = [
        f for f in findings if f.get("reachable") or f.get("taint") == "tainted"
    ]

    if not highlighted:
        lines.append(
            "No reachable vulnerabilities: no known CVE in a declared dependency "
            "is reachable from a public entry point."
        )
        return "\n".join(lines)

    lines.append(
        "| Dependency | CVE | Severity | Verdict | Symbol match | Taint | Fixed |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for finding in highlighted[:_MARKDOWN_TABLE_CAP]:
        fixed = ", ".join(finding.get("fixed_versions") or []) or "—"
        lines.append(
            "| "
            + " | ".join(
                _md_cell(cell)
                for cell in (
                    _dep_at_version(finding),
                    _cve_label(finding),
                    finding.get("severity") or "UNKNOWN",
                    finding.get("verdict") or "",
                    finding.get("symbol_match") or "",
                    finding.get("taint") or "",
                    fixed,
                )
            )
            + " |"
        )

    remainder = len(highlighted) - _MARKDOWN_TABLE_CAP
    if remainder > 0:
        lines.append("")
        lines.append(f"_…and {remainder} more reachable finding(s) not shown._")

    return "\n".join(lines)
