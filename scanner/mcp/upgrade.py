"""Safe, surgical manifest pin editing for ``vscan_apply_upgrade``.

The contract is deliberately conservative: locate exactly **one** unambiguous
pin for a dependency in its declared manifest and rewrite only that version
token, leaving every other character (comments, ordering, whitespace, other
requirements) untouched. If the pin cannot be located unambiguously -- zero
matches, several matches, or a version *range* rather than an exact pin -- we
refuse with a message that names the file (and line, when known) so the agent
can edit it by hand instead of us guessing.

Supported safe cases:

* ``requirements*.txt`` / ``*.in`` / constraints:   ``name==x.y.z`` pins
* ``pyproject.toml``:                               ``"name==x.y.z"`` pins
* ``package.json``:                                 exact ``"name": "x.y.z"``

Nothing here consults the network; it only reads/writes the one manifest file.
"""

from __future__ import annotations

import difflib
import os
import re
from typing import Any

from scanner.graph import Node

from .state import ToolError

# Characters that mark an npm spec as a *range* rather than an exact pin.
_NPM_RANGE_TOKENS = ("^", "~", ">", "<", "*", "||", " ", "x", "X", " - ")

# A PEP 508-ish ``name[extras]==version`` occurrence anywhere on a line.
_PIN_RE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?P<extras>\[[^\]]*\])?"
    r"\s*==\s*"
    r"(?P<ver>[A-Za-z0-9][A-Za-z0-9._!+*-]*)"
)


def _norm(name: str) -> str:
    """PEP 503 normalization so ``PyYAML`` matches ``pyyaml`` / ``py-yaml``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def version_key(version: str) -> tuple[int, ...]:
    """A best-effort orderable key from the leading numeric components.

    ``"5.3.1" -> (5, 3, 1)``. Non-numeric suffixes (pre-releases) are ignored
    for ordering, which is adequate for picking the smallest clearing release
    from the published ``fixed_versions`` list.
    """
    parts: list[int] = []
    for token in re.split(r"[._-]", version.strip()):
        m = re.match(r"\d+", token)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def recommend_fixed_version(per_cve_fixed: list[list[str]]) -> str | None:
    """Smallest single version that clears every CVE for a dependency.

    Each inner list is one CVE's published ``fixed_versions``. To clear a CVE
    you must move to at least its smallest fixed release; to clear *all* CVEs
    you need the maximum of those per-CVE minimums. Returns ``None`` when no CVE
    publishes a fixed version.
    """
    per_cve_minimums: list[str] = []
    for fixed in per_cve_fixed:
        candidates = [v for v in fixed if v and version_key(v)]
        if not candidates:
            # A CVE with no published fix cannot be cleared by upgrading.
            return None
        per_cve_minimums.append(min(candidates, key=version_key))
    if not per_cve_minimums:
        return None
    return max(per_cve_minimums, key=version_key)


def _strip_comment(line: str) -> str:
    """Return the part of a line before an ``#`` comment (good enough here)."""
    idx = line.find("#")
    return line if idx < 0 else line[:idx]


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _edit_requirement_style(
    text: str, name: str, new_version: str, source_file: str
) -> tuple[str, int]:
    """Rewrite the single ``name==...`` pin in requirements/pyproject text."""
    target = _norm(name)
    hits: list[tuple[int, int, str]] = []  # (abs_start_of_ver, abs_end_of_ver, old_ver)
    offset = 0
    for line in text.splitlines(keepends=True):
        scannable = _strip_comment(line)
        for m in _PIN_RE.finditer(scannable):
            if _norm(m.group("name")) == target:
                hits.append(
                    (offset + m.start("ver"), offset + m.end("ver"), m.group("ver"))
                )
        offset += len(line)

    if not hits:
        raise ToolError(
            f"no exact '{name}==<version>' pin found in {source_file}. "
            "The dependency may use a range or be declared elsewhere; "
            "edit the manifest manually."
        )
    if len(hits) > 1:
        lines = sorted({_line_of_offset(text, h[0]) for h in hits})
        raise ToolError(
            f"found {len(hits)} '{name}==' pins in {source_file} "
            f"(lines {lines}); refusing to guess. Edit the intended line manually."
        )

    start, end, old_ver = hits[0]
    if old_ver == new_version:
        raise ToolError(
            f"{name} is already pinned to {new_version} in {source_file}; nothing to do."
        )
    new_text = text[:start] + new_version + text[end:]
    return new_text, _line_of_offset(text, start)


def _edit_json(
    text: str, name: str, new_version: str, source_file: str
) -> tuple[str, int]:
    """Rewrite the single exact ``"name": "x.y.z"`` entry in package.json text."""
    value_re = re.compile(
        r'("' + re.escape(name) + r'"\s*:\s*")(?P<spec>[^"]*)(")'
    )
    matches = list(value_re.finditer(text))
    if not matches:
        raise ToolError(
            f"no \"{name}\": \"<version>\" entry found in {source_file}. "
            "Check the dependency name/casing; edit the manifest manually."
        )
    if len(matches) > 1:
        lines = sorted({_line_of_offset(text, m.start()) for m in matches})
        raise ToolError(
            f"found {len(matches)} \"{name}\" entries in {source_file} "
            f"(lines {lines}); refusing to guess. Edit the intended line manually."
        )
    m = matches[0]
    spec = m.group("spec")
    if any(tok in spec for tok in _NPM_RANGE_TOKENS):
        line = _line_of_offset(text, m.start())
        raise ToolError(
            f"{name} uses a range spec '{spec}' (not an exact pin) in {source_file} "
            f"line {line}; refusing to rewrite a range. Edit the manifest manually."
        )
    if spec == new_version:
        raise ToolError(
            f"{name} is already set to {new_version} in {source_file}; nothing to do."
        )
    start, end = m.start("spec"), m.end("spec")
    new_text = text[:start] + new_version + text[end:]
    return new_text, _line_of_offset(text, start)


def plan_upgrade(
    repo_abspath: str, dep_node: Node, new_version: str
) -> dict[str, Any]:
    """Locate the pin and compute the edited manifest + unified diff.

    Does NOT write anything. Returns a dict with ``source_file``, ``abspath``,
    ``line``, ``old_text``, ``new_text`` and ``diff`` (unified). Raises
    :class:`ToolError` (actionable message) when the edit is unsafe/ambiguous.
    """
    if not new_version or not new_version.strip():
        raise ToolError("version is required (e.g. '5.4.1').")
    new_version = new_version.strip()

    source_file = dep_node.attrs.get("source_file")
    if not source_file:
        raise ToolError(
            f"dependency {dep_node.id} has no recorded manifest (source_file); "
            "cannot locate a pin to edit."
        )
    abspath = os.path.join(repo_abspath, source_file)
    if not os.path.isfile(abspath):
        raise ToolError(
            f"manifest file not found: {source_file} (expected at {abspath})."
        )
    try:
        original = open(abspath, encoding="utf-8").read()
    except OSError as exc:
        raise ToolError(f"could not read {source_file}: {exc}") from exc

    base = os.path.basename(source_file).lower()
    if base.endswith(".json"):
        new_text, line = _edit_json(original, dep_node.name, new_version, source_file)
    else:
        new_text, line = _edit_requirement_style(
            original, dep_node.name, new_version, source_file
        )

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{source_file}",
            tofile=f"b/{source_file}",
        )
    )
    return {
        "source_file": source_file,
        "abspath": abspath,
        "line": line,
        "old_text": original,
        "new_text": new_text,
        "diff": diff,
    }


def write_upgrade(abspath: str, new_text: str) -> None:
    try:
        with open(abspath, "w", encoding="utf-8") as fh:
            fh.write(new_text)
    except OSError as exc:
        raise ToolError(f"could not write {abspath}: {exc}") from exc
