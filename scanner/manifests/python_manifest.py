"""Python manifest adapter (DEEP): requirements*.txt, pyproject.toml, Pipfile.

Emits PyPI dependencies. Declared versions come from the manifest (a
``requirements.txt`` line, ``[project].dependencies``, ``[tool.poetry]`` or a
``Pipfile``). When a sibling lockfile is present the resolved tree is also
enumerated: ``poetry.lock`` beside a poetry ``pyproject.toml`` and
``Pipfile.lock`` beside a ``Pipfile``. Packages the manifest does not declare
itself are emitted as ``direct=False`` (the soundness key: a transitive dep is
never ruled unreachable). A plain ``requirements.txt`` carries no
direct/transitive signal, so every entry there stays ``direct=True``.
"""

from __future__ import annotations

import json
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

# PEP 503 normalisation: a run of ``-``, ``_`` or ``.`` collapses to a single
# ``-`` and the name is lowercased. Used only to compare DECLARED vs LOCKED
# names so e.g. declared ``PyYAML`` matches locked ``pyyaml`` and that package
# is not double-emitted as a transitive dep.
_PEP503_SEP = re.compile(r"[-_.]+")


def _normalize_pep503(name: str) -> str:
    return _PEP503_SEP.sub("-", name).lower()


def _sibling_relpath(manifest_relpath: str, filename: str) -> str:
    """Repo-relative path of ``filename`` next to ``manifest_relpath``."""
    directory = os.path.dirname(manifest_relpath)
    return f"{directory}/{filename}" if directory else filename


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


def _transitive_from_poetry_lock(
    manifest_abspath: str, manifest_relpath: str, declared_norm: set[str]
) -> list[Dependency]:
    """Enumerate a sibling ``poetry.lock`` tree, minus the declared packages.

    Each ``[[package]]`` entry has a ``name`` and a resolved ``version``. Every
    locked package whose PEP 503-normalised name is not already declared is
    emitted as ``direct=False`` (transitive). Missing/malformed lock files
    yield nothing rather than raising.
    """
    lock_abspath = os.path.join(os.path.dirname(manifest_abspath), "poetry.lock")
    if not os.path.isfile(lock_abspath):
        return []
    lock_relpath = _sibling_relpath(manifest_relpath, "poetry.lock")
    try:
        with open(lock_abspath, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return []

    out: list[Dependency] = []
    seen: set[str] = set()
    for pkg in data.get("package", []) or []:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        norm = _normalize_pep503(name)
        if norm in declared_norm or norm in seen:
            continue
        seen.add(norm)
        out.append(
            Dependency(name, version, "PyPI", lock_relpath, resolved=True, direct=False)
        )
    return out


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

    # Transitive dependencies: for a poetry project ([tool.poetry] present),
    # enumerate the sibling poetry.lock and emit every locked package the
    # manifest does not declare as direct=False -- the soundness key. Declared
    # vs locked names are compared PEP 503-normalised so a declared "PyYAML"
    # matches a locked "pyyaml" and is not double-emitted as transitive.
    if poetry:
        declared_norm = {_normalize_pep503(dep.name) for dep in deps}
        deps.extend(_transitive_from_poetry_lock(abspath, relpath, declared_norm))

    return deps


def _transitive_from_pipfile_lock(
    manifest_abspath: str, manifest_relpath: str, declared_norm: set[str]
) -> list[Dependency]:
    """Enumerate a sibling ``Pipfile.lock`` (JSON), minus declared packages.

    ``default`` and ``develop`` map a package name to ``{"version": "==x.y.z"}``;
    the leading ``==`` is stripped to a bare version. Every locked package whose
    PEP 503-normalised name is not already declared is emitted as
    ``direct=False``. Missing/malformed lock files yield nothing.
    """
    lock_abspath = os.path.join(os.path.dirname(manifest_abspath), "Pipfile.lock")
    if not os.path.isfile(lock_abspath):
        return []
    lock_relpath = _sibling_relpath(manifest_relpath, "Pipfile.lock")
    try:
        with open(lock_abspath, encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[Dependency] = []
    seen: set[str] = set()
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if not isinstance(name, str):
                continue
            norm = _normalize_pep503(name)
            if norm in declared_norm or norm in seen:
                continue
            version = "*"
            if isinstance(meta, dict):
                raw = meta.get("version")
                if isinstance(raw, str) and raw.strip():
                    raw = raw.strip()
                    version = raw[2:] if raw.startswith("==") else raw
            seen.add(norm)
            out.append(
                Dependency(name, version, "PyPI", lock_relpath, resolved=True, direct=False)
            )
    return out


def _parse_pipfile(abspath: str, relpath: str) -> list[Dependency]:
    """Parse a ``Pipfile`` (TOML) + its sibling ``Pipfile.lock``.

    ``[packages]`` and ``[dev-packages]`` are the declared (direct) deps; the
    lock file supplies the rest of the resolved tree as transitive deps.
    """
    deps: list[Dependency] = []
    try:
        with open(abspath, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return deps

    declared_norm: set[str] = set()
    for section in ("packages", "dev-packages"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, constraint in block.items():
            if not isinstance(name, str):
                continue
            version, declared = _spec_from_poetry(constraint)
            deps.append(
                Dependency(name, version, "PyPI", relpath, resolved=False, declared=declared)
            )
            declared_norm.add(_normalize_pep503(name))

    deps.extend(_transitive_from_pipfile_lock(abspath, relpath, declared_norm))
    return deps


@register
class PythonManifestAdapter(ManifestAdapter):
    """Adapter for Python requirements files, pyproject.toml and Pipfile."""

    ecosystem = "PyPI"

    def matches(self, relpath: str) -> bool:
        base = os.path.basename(relpath)
        if base in {"pyproject.toml", "Pipfile"}:
            return True
        return base.startswith("requirements") and base.endswith(".txt")

    def parse(self, abspath: str, relpath: str) -> list[Dependency]:
        base = os.path.basename(relpath)
        if base == "pyproject.toml":
            return _parse_pyproject(abspath, relpath)
        if base == "Pipfile":
            return _parse_pipfile(abspath, relpath)
        return _parse_requirements(abspath, relpath, set())
