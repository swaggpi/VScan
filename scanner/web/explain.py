"""Grounded attack-narrative + remediation for a single scan finding.

This module is the advisory brain behind ``POST /api/explain``. It is kept
deliberately free of any web framework (no FastAPI import) so the phrasing
logic can be unit-tested without the server's heavy runtime deps, and so the
transport layer (:mod:`scanner.web.app`) only has to look a finding up and hand
it here.

Nothing in here produces or alters a reachability / taint / verdict decision.
It is a pure *reader*: it takes one finding dict exactly as
:func:`scanner.correlate.report.audit` emits it (``asdict`` of a
:class:`~scanner.correlate.Finding` plus the three-way ``verdict`` key) and
renders an attacker's-eye narrative plus a concrete upgrade, grounded ONLY in
that finding's own facts.

Two things generate the prose:

* the configured model, via :class:`scanner.agent.LLMClient.complete_json`
  (strict JSON ``{narrative, remediation}``) -- provenance ``"llm"``; and
* a deterministic template over the SAME facts -- provenance
  ``"offline-heuristic"`` -- used verbatim when no model is configured or the
  model returns nothing usable. The fallback is a real grounded rendering, not
  a placeholder.

The response verdict tier is derived here (and only here) from fields the
analyzer already set, never recomputed:

* ``taint == "tainted"``           -> ``"exploitable"``
* else ``reachable is True``       -> ``"reachable"``
* else                             -> ``"not_reached"``

The CARDINAL RULE -- phrase the facts, never invent a path, entrypoint, verdict
or fix -- is enforced two ways: the model is told so explicitly and is only
ever given the finding's real facts to work from, and the offline template can
physically only emit what the facts contain.
"""

from __future__ import annotations

import os
import re
from typing import Any

# Response verdict tiers (distinct from the finding's own three-way reachability
# ``verdict`` field; these describe exploitability for the UI).
EXPLOITABLE = "exploitable"
REACHABLE = "reachable"
NOT_REACHED = "not_reached"

# Human brand label for the model field. Meta branding is wanted now; the exact
# model id is appended from the env the LLM client also reads.
_MODEL_BRAND = "Meta Muse"


def model_label() -> str:
    """A human, branded label for the configured model, e.g. ``Meta Muse (x)``.

    Reads the same ``LLM_MODEL`` env the :class:`~scanner.agent.LLMClient` uses.
    When unset the label degrades to ``"Meta Muse"`` with an empty parenthetical
    rather than inventing a model name.
    """
    model = (os.environ.get("LLM_MODEL") or "").strip()
    return f"{_MODEL_BRAND} ({model})" if model else _MODEL_BRAND


def response_verdict(finding: dict[str, Any]) -> str:
    """Map a finding's analyzer fields to the exploitability tier for the API.

    Reads only already-decided fields; it never re-derives reachability/taint.
    """
    if finding.get("taint") == "tainted":
        return EXPLOITABLE
    if finding.get("reachable") is True:
        return REACHABLE
    return NOT_REACHED


def find_finding(
    findings: list[dict[str, Any]], dependency_id: str, vuln_id: str
) -> dict[str, Any] | None:
    """Return the finding matching ``(dependency_id, vuln_id)`` or ``None``."""
    for finding in findings:
        if (
            finding.get("dependency_id") == dependency_id
            and finding.get("vuln_id") == vuln_id
        ):
            return finding
    return None


# --------------------------------------------------------------------------
# Fact rendering helpers (shared by the prompt and the offline template)
# --------------------------------------------------------------------------


def _dep_label(finding: dict[str, Any]) -> str:
    """``name@version`` when a version is known, else just the name."""
    name = finding.get("dependency_name") or finding.get("dependency_id") or "the dependency"
    version = finding.get("version")
    return f"{name}@{version}" if version else name


def _cve_label(finding: dict[str, Any]) -> str:
    """A readable advisory id: the CVE list if present, else the raw vuln id."""
    cves = [c for c in (finding.get("cve_ids") or []) if c]
    if cves:
        return ", ".join(cves)
    return finding.get("vuln_id") or "the advisory"


def _taint_path(finding: dict[str, Any]) -> list[str]:
    """The proven source->sink hop list, if the finding carries taint evidence."""
    evidence = finding.get("taint_evidence")
    if isinstance(evidence, dict):
        path = evidence.get("path")
        if isinstance(path, list):
            return [str(hop) for hop in path if hop]
    return []


def _fixed_versions(finding: dict[str, Any]) -> list[str]:
    return [str(v) for v in (finding.get("fixed_versions") or []) if v]


# --------------------------------------------------------------------------
# Prompt construction (the model phrases these facts; it invents nothing)
# --------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a security advisor explaining one dependency vulnerability finding "
    "to an engineer. You are given a fixed set of FACTS already decided by a "
    "static reachability and taint analysis. Your job is only to phrase those "
    "facts clearly, as an attack narrative plus a remediation.\n\n"
    "HARD RULES:\n"
    "- Use ONLY the facts provided. Never invent a call path, entry point, "
    "source, sink, CVE, version, or fix that is not in the facts.\n"
    "- Do not change the verdict. If the facts say the vulnerable code is "
    "reachable but attacker input was NOT proven to reach it, do NOT claim it "
    "is exploitable. If the facts say nothing reaches the package, say static "
    "analysis found no resolved public call path reaching it (a lower bound, "
    "not a proof of safety) -- never claim it is or is not exploitable.\n"
    "- Keep it concrete and short (a few sentences each). No markdown headings.\n"
    "- Respond with STRICT JSON and nothing else: "
    '{"narrative": "<string>", "remediation": "<string>"}.'
)


def _facts_block(finding: dict[str, Any], verdict: str) -> str:
    """The grounding facts handed to the model, one per line."""
    lines: list[str] = [
        f"dependency: {_dep_label(finding)}",
        f"ecosystem: {finding.get('ecosystem') or 'unknown'}",
        f"advisory: {finding.get('vuln_id') or 'unknown'}",
        f"cve_ids: {', '.join(finding.get('cve_ids') or []) or 'none'}",
        f"summary: {finding.get('summary') or 'none'}",
        f"severity: {finding.get('severity') or 'unknown'}",
        f"cvss_vector: {finding.get('cvss_vector') or 'none'}",
        f"known_exploited (KEV): {bool(finding.get('kev'))}",
        f"epss: {finding.get('epss') if finding.get('epss') is not None else 'unknown'}",
        f"verdict_tier: {verdict}",
        f"fixed_versions: {', '.join(_fixed_versions(finding)) or 'none published'}",
    ]

    details = finding.get("details")
    if isinstance(details, str) and details.strip():
        lines.append(f"cve_details: {details.strip()}")

    if verdict == EXPLOITABLE:
        evidence = finding.get("taint_evidence") or {}
        path = _taint_path(finding)
        lines.append("reachability: attacker-controlled input is PROVEN to flow "
                     "into a call into this dependency (tainted).")
        lines.append(f"taint_entrypoint: {evidence.get('entrypoint') or 'unknown'}")
        lines.append(f"taint_source: {evidence.get('source') or 'unknown'}")
        lines.append(f"taint_sink_symbol: {evidence.get('sink_symbol') or 'unknown'}")
        lines.append(f"taint_path: {' -> '.join(path) if path else 'unknown'}")
    elif verdict == REACHABLE:
        entries = ", ".join(finding.get("reachable_entrypoints") or []) or "a public entry point"
        path = finding.get("example_path") or []
        lines.append("reachability: the vulnerable package is REACHABLE from an "
                     "entry point, but attacker-controlled input was NOT proven "
                     "to reach the vulnerable code (not exploitable as proven).")
        lines.append(f"reachable_entrypoints: {entries}")
        lines.append(
            "example_path: "
            + (" -> ".join(str(h) for h in path) if path else "unknown")
        )
    else:  # NOT_REACHED
        lines.append("reachability: no resolved public call path reaches this "
                     "package in the scanned code, so static analysis did not "
                     "find it reachable. This is a lower bound, not a proof of "
                     "safety -- do not claim it is (or is not) exploitable.")

    return "\n".join(lines)


def build_prompt(finding: dict[str, Any], verdict: str) -> tuple[str, str]:
    """Return ``(system_prompt, user_prompt)`` grounded in the finding's facts."""
    if verdict == EXPLOITABLE:
        ask = (
            "Write a narrative that walks the proven taint path from the entry "
            "point through the source to the sink symbol, explaining how an "
            "attacker reaches the vulnerable code. Then write a remediation that "
            "upgrades to a fixed version and says why that closes this path."
        )
    elif verdict == REACHABLE:
        ask = (
            "Write a narrative that says the vulnerable code is reachable via the "
            "listed entry point(s)/path, but make clear attacker-controlled input "
            "was NOT proven to reach it, so exploitability is unconfirmed -- do "
            "not claim it is exploitable. Then write a remediation that upgrades "
            "to a fixed version and says why that removes the risk."
        )
    else:
        ask = (
            "Write a narrative that says the CVE exists in this dependency but "
            "no resolved public call path reaches the package in the scanned "
            "code, so static analysis did not find it reachable. Make clear this "
            "is a lower bound, not a proof of safety, and do NOT claim it is (or "
            "is not) exploitable. Then write a remediation that upgrades to a "
            "fixed version for defense-in-depth / future-proofing."
        )

    user = (
        "FACTS:\n"
        f"{_facts_block(finding, verdict)}\n\n"
        f"TASK:\n{ask}\n\n"
        'Respond with strict JSON: {"narrative": "...", "remediation": "..."}'
    )
    return _SYSTEM_PROMPT, user


# --------------------------------------------------------------------------
# Deterministic offline fallback (a real grounded rendering, not a stub)
# --------------------------------------------------------------------------


def _remediation_text(finding: dict[str, Any], verdict: str) -> str:
    dep = finding.get("dependency_name") or "the dependency"
    fixed = _fixed_versions(finding)
    if fixed:
        target = fixed[0]
        base = f"Upgrade {dep} to {target} or later (fixed: {', '.join(fixed)})."
    else:
        base = (
            f"No fixed version is published for {dep} yet; track the advisory "
            f"({_cve_label(finding)}) and apply a patched release as soon as one "
            "ships, or remove/replace the dependency."
        )
    if not fixed:
        return base
    if verdict == EXPLOITABLE:
        return base + " This closes the proven path from the entry point to the vulnerable code."
    if verdict == REACHABLE:
        return base + " This removes the reachable vulnerable code before input can ever be proven to reach it."
    return base + " The package is not currently reachable, but upgrading removes the latent risk."


def offline_explanation(
    finding: dict[str, Any], verdict: str
) -> tuple[str, str]:
    """Render ``(narrative, remediation)`` from the finding's facts, no model.

    Grounded strictly in the provided facts for each verdict tier.
    """
    dep = _dep_label(finding)
    cve = _cve_label(finding)
    summary = finding.get("summary") or "a known vulnerability"
    severity = finding.get("severity")
    sev_clause = f" ({severity})" if severity else ""

    if verdict == EXPLOITABLE:
        evidence = finding.get("taint_evidence") or {}
        path = _taint_path(finding)
        entrypoint = evidence.get("entrypoint") or "a public entry point"
        source = evidence.get("source") or "attacker-controlled input"
        sink = evidence.get("sink_symbol") or "the vulnerable function"
        chain = " -> ".join(path) if path else f"{entrypoint} -> {sink}"
        narrative = (
            f"{dep} is affected by {cve}{sev_clause}: {summary}. "
            f"This finding is exploitable: attacker-controlled input from {source} "
            f"at the entry point {entrypoint} is proven to flow into {sink}, the "
            f"vulnerable code in {finding.get('dependency_name') or 'the dependency'}. "
            f"The proven path is: {chain}."
        )
    elif verdict == REACHABLE:
        entries = finding.get("reachable_entrypoints") or []
        entries_text = ", ".join(entries) if entries else "a public entry point"
        path = finding.get("example_path") or []
        path_clause = (
            f" An example call path is: {' -> '.join(str(h) for h in path)}."
            if path
            else ""
        )
        narrative = (
            f"{dep} is affected by {cve}{sev_clause}: {summary}. "
            f"The vulnerable package is reachable from {entries_text}.{path_clause} "
            "However, attacker-controlled input was NOT proven to reach the "
            "vulnerable code, so exploitability is unconfirmed -- treat this as "
            "reachable-but-not-proven rather than confirmed exploitable."
        )
    else:  # NOT_REACHED
        narrative = (
            f"{dep} is affected by {cve}{sev_clause}: {summary}. "
            "No resolved public call path reaches this package in the scanned "
            "code, so static analysis did not find it reachable. This is a lower "
            "bound, not a proof of safety. It remains a latent risk if the code "
            "later starts calling into the affected package."
        )

    return narrative, _remediation_text(finding, verdict)


# --------------------------------------------------------------------------
# Negation-aware exploitability guard (cardinal rule, advisory-only)
# --------------------------------------------------------------------------
#
# For a NON-exploitable verdict (reachable / not_reached) the model's prose must
# never affirmatively claim the finding is exploitable -- doing so would present
# a false "exploitable". :func:`_claims_exploitable` spots an UNNEGATED
# exploitability assertion so :func:`explain_finding` can discard the LLM
# rendering and fall back to the provably-grounded offline template (always
# safe). It is deliberately conservative: a negation within ~25 chars before (or
# inside) a match clears it, because correct reachable narratives routinely say
# "reachable but NOT proven exploitable". It never touches the deterministic
# verdict -- it only chooses which rendering (LLM vs offline) to return. A rare
# false trigger only costs us the model's phrasing; the fallback is grounded.

# Chars of leading context scanned for a negation ahead of a match.
_NEG_WINDOW = 25

# A negation anywhere in ``[match_start - _NEG_WINDOW, match_end]`` clears the
# match (covers "not"/"no"/"never"/"cannot"/"without"/"un-" and ``n't``
# contractions such as "can't"/"isn't"/"aren't").
_NEGATION = re.compile(
    r"\b(?:not|never|no|none|cannot|without|unproven|unconfirmed|unable|unlikely)\b"
    r"|n't",
    re.IGNORECASE,
)

# Affirmative assertions of exploitability. Each is only treated as a real claim
# when no negation sits in its negation window (see :func:`_claims_exploitable`).
_EXPLOIT_CLAIMS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bexploitable\b", re.IGNORECASE),
    re.compile(r"\bcan\s+be\s+exploited\b", re.IGNORECASE),
    re.compile(r"\bexploit\s+this\b", re.IGNORECASE),
    re.compile(r"\bproven\s+(?:taint|exploit|flow|path)", re.IGNORECASE),
    re.compile(r"\bsource\s*(?:->|→|to)\s*sink\b", re.IGNORECASE),
    # Remote / arbitrary code execution asserted of the shown code (standalone,
    # so a bare "arbitrary code execution" or "RCE" also counts), plus the
    # common abbreviation. Negation-awareness still clears "no RCE" etc.
    re.compile(r"\b(?:remote|arbitrary)\s+code\s+execution\b", re.IGNORECASE),
    re.compile(r"\bRCE\b", re.IGNORECASE),
    re.compile(
        r"\battacker\b[^.!?\n]{0,30}?\b(?:can|is\s+able\s+to|able\s+to|proven)\b"
        r"[^.!?\n]{0,30}?\b(?:execute|reach|run|inject)\b",
        re.IGNORECASE,
    ),
    # "is vulnerable to <X> and can be [exploited/...]" -- a compound affirmative.
    re.compile(
        r"\bvulnerable\s+to\b[^.!?\n]{0,80}?\band\s+can\s+be\b",
        re.IGNORECASE,
    ),
)


def _claims_exploitable(text: str) -> bool:
    """True if ``text`` affirmatively (un-negated) asserts exploitability.

    Each affirmative phrase (see :data:`_EXPLOIT_CLAIMS`) counts only when no
    negation (``not`` / ``n't`` / ``no`` / ``never`` / ``cannot`` / ``without``
    / ``un-`` ...) appears within ~25 chars before it or inside the matched
    span. This lets the standard reachable-tier phrasing -- "reachable but NOT
    proven exploitable" -- pass, while catching a bare "this is exploitable
    (proven taint path)". Conservative by design: it errs toward NOT flagging
    unless the claim is clearly affirmative.
    """
    if not isinstance(text, str) or not text:
        return False
    for pattern in _EXPLOIT_CLAIMS:
        for match in pattern.finditer(text):
            window = text[max(0, match.start() - _NEG_WINDOW) : match.end()]
            if not _NEGATION.search(window):
                return True
    return False


# --------------------------------------------------------------------------
# Top-level: produce the full /api/explain response body for one finding
# --------------------------------------------------------------------------


def _valid_llm_payload(data: Any) -> tuple[str, str] | None:
    """Return ``(narrative, remediation)`` if ``data`` is a usable model reply."""
    if not isinstance(data, dict):
        return None
    narrative = data.get("narrative")
    remediation = data.get("remediation")
    if (
        isinstance(narrative, str)
        and narrative.strip()
        and isinstance(remediation, str)
        and remediation.strip()
    ):
        return narrative.strip(), remediation.strip()
    return None


def explain_finding(finding: dict[str, Any], client: Any) -> dict[str, Any]:
    """Build the 200 response body for one finding.

    Tries the configured model first (strict JSON ``{narrative, remediation}``);
    on an unavailable client or any invalid/empty reply, falls back to the
    deterministic grounded template. Never raises.
    """
    verdict = response_verdict(finding)

    narrative: str | None = None
    remediation: str | None = None
    provenance = "offline-heuristic"

    try:
        if client is not None and client.available():
            system_prompt, user_prompt = build_prompt(finding, verdict)
            data = client.complete_json(system_prompt, user_prompt)
            usable = _valid_llm_payload(data)
            if usable is not None:
                narrative, remediation = usable
                provenance = "llm"
                # Cardinal-rule guard: for a non-exploitable verdict, never let
                # the model's prose affirm exploitability. If it does, discard
                # the LLM rendering and fall back to the provably-grounded
                # offline template (below). This chooses the rendering only; it
                # never changes the deterministic verdict.
                if verdict != EXPLOITABLE and _claims_exploitable(
                    f"{narrative}\n{remediation}"
                ):
                    narrative = remediation = None
                    provenance = "offline-heuristic"
    except Exception:  # noqa: BLE001 - never let the model path break the response
        narrative = remediation = None
        provenance = "offline-heuristic"

    if narrative is None or remediation is None:
        narrative, remediation = offline_explanation(finding, verdict)
        provenance = "offline-heuristic"

    return {
        "dependency_id": finding.get("dependency_id"),
        "vuln_id": finding.get("vuln_id"),
        "dependency_name": finding.get("dependency_name"),
        "cve_ids": list(finding.get("cve_ids") or []),
        "verdict": verdict,
        "narrative": narrative,
        "remediation": remediation,
        "provenance": provenance,
        # Honest label: only name the model when it actually produced the prose.
        # On the offline-heuristic path no model ran, so never show the brand.
        "model": model_label() if provenance == "llm" else "offline heuristic",
    }
