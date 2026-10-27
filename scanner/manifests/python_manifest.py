"""Python manifest adapter (DEEP): requirements*.txt and pyproject.toml.

Emits PyPI dependencies. Versions are *declared* (Python manifests do not carry
resolved versions; a poetry.lock / pip freeze resolution would be a future
extension), so ``resolved`` is always ``False`` here.
"""

from __future__ import annotations

import os
import re
import tomllib

from . import Dependency, ManifestAdapter, register

# PEP 508 / requirement line: name, optional extras, optional version spec.
_REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<spec>[<>=!~][^;#]*)?"
)

# A single comparator + version at the start of a spec, used to pull out an
# exact pin for display while still recording the full declared constraint.
_FIRST_PIN = re.compile(r"^\s*(==|>=|<=|~=|!=|>|<|===)\s*([A-Za-z0-9][A-Za-z0-9._*+!-]*)")


def _clean_version(spec: str | None) -> tuple[str, str]:
    """Return ``(display_version, declared_spec)`` from a raw version spec.

    For an exact pin (``==1.2.3``) the display version is ``1.2.3``. For any
    other constraint the display version is the whole constraint string.
    """
    if not spec:
        return ("*", "*")
    declared = spec.strip()
    match = _FIRST_PIN.match(declared)
    if match and match.group(1) in {"==", "==="}:
        # Only a single exact pin becomes a bare version; compound specs such as
        # ">=1.0,<2.0" keep their full text.
        if "," not in declared:
            return (match.group(2), declared)
    return (declared, declared)


def _parse_requirements(abspath: str, relpath: str, _seen: set[str]) -> list[Dependency]:
    """Parse a requirements file, following ``-r``/``--requirement`` includes."""
    if abspath in _seen:
        return []
    _seen.add(abspath)

    deps: list[Dependency] = []
    try:
        with open(abspath, encoding="utf-8", errors="replace") as handle:
            raw_lines = handle.readlines()
    except OSError:
        return deps

    base_dir = os.path.dirname(abspath)
    for raw in raw_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Includes: -r other.txt / --requirement other.txt.
        include_match = re.match(r"^(?:-r|--requirement)\s+(\S+)", line)
        if include_match:
            inc_path = os.path.normpath(os.path.join(base_dir, include_match.group(1)))
            if os.path.isfile(inc_path):
                deps.extend(_parse_requirements(inc_path, relpath, _seen))
            continue
        # Other pip options (-e, --hash, -c, ...) are out of scope here.
        if line.startswith("-"):
            continue
        # Strip inline comments and environment markers for the name/version.
        line = line.split(" #", 1)[0].strip()
        match = _REQ_LINE.match(line)
        if not match or not match.group("name"):
            continue
        version, declared = _clean_version(match.group("spec"))
        deps.append(
            Dependency(
                name=match.group("name"),
                version=version,
                ecosystem="PyPI",
                source_file=relpath,
                resolved=False,
                declared=declared,
            )
        )
    return deps


def _spec_from_poetry(constraint) -> tuple[str, str]:
    """Normalise a poetry dependency constraint value to (version, declared).

    Only an exact pin (``==1.2`` or a bare ``1.2``) collapses to a bare version;
    caret/tilde/range constraints (``^1.2``, ``~1.2``, ``>=1,<2``) are kept
    verbatim, consistent with the requirements.txt path. Poetry dependency
    *groups* and *optional*/extras metadata are intentionally not collected at
    this layer.
    """
    if isinstance(constraint, str):
        return _clean_version(constraint)
    if isinstance(constraint, dict):
        version = constraint.get("version")
        if isinstance(version, str) and version.strip():
            return _clean_version(version)
        return ("*", "*")
    return ("*", "*")


def _parse_pep508(entry: str) -> tuple[str, str, str] | None:
    """Parse a ``[project].dependencies`` entry -> (name, version, declared)."""
    match = _REQ_LINE.match(entry)
    if not match or not match.group("name"):
        return None
    version, declared = _clean_version(match.group("spec"))
    return (match.group("name"), version, declared)


def _parse_pyproject(abspath: str, relpath: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        with open(abspath, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return deps

    # PEP 621 [project].dependencies (list of PEP 508 strings).
    project = data.get("project", {})
    for entry in project.get("dependencies", []) or []:
        if not isinstance(entry, str):
            continue
        parsed = _parse_pep508(entry)
        if parsed:
            name, version, declared = parsed
            deps.append(
                Dependency(name, version, "PyPI", relpath, resolved=False, declared=declared)
            )

    # [tool.poetry.dependencies] (mapping name -> constraint).
    poetry = data.get("tool", {}).get("poetry", {})
    for name, constraint in (poetry.get("dependencies", {}) or {}).items():
        if name.lower() == "python":  # the interpreter constraint, not a dep
            continue
        version, declared = _spec_from_poetry(constraint)
        deps.append(
            Dependency(name, version, "PyPI", relpath, resolved=False, declared=declared)
        )

    return deps


@register
class PythonManifestAdapter(ManifestAdapter):
    """Adapter for Python requirements files and pyproject.toml."""

    ecosystem = "PyPI"

    def matches(self, relpath: str) -> bool:
        base = os.path.basename(relpath)
        if base == "pyproject.toml":
            return True
        return base.startswith("requirements") and base.endswith(".txt")

    def parse(self, abspath: str, relpath: str) -> list[Dependency]:
        base = os.path.basename(relpath)
        if base == "pyproject.toml":
            return _parse_pyproject(abspath, relpath)
        return _parse_requirements(abspath, relpath, set())
