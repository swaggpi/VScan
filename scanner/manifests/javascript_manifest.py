"""JavaScript manifest adapter (DEEP): package.json + lockfiles.

Emits npm dependencies. Declared versions come from ``package.json``
(``dependencies`` and ``devDependencies``). When a sibling lockfile is present
(``package-lock.json`` preferred, then ``pnpm-lock.yaml`` best-effort) the
resolved exact version replaces the declared range and ``resolved`` is set.
"""

from __future__ import annotations

import json
import os
import re

from . import Dependency, ManifestAdapter, register


def _load_json(abspath: str) -> dict | None:
    try:
        with open(abspath, encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _resolved_from_package_lock(abspath: str) -> dict[str, str]:
    """Return ``{name: version}`` from a package-lock.json (v1, v2 or v3)."""
    data = _load_json(abspath)
    if not data:
        return {}
    resolved: dict[str, str] = {}

    # npm v7+ ("lockfileVersion" 2/3): the "packages" map keyed by install path.
    # Prefer the hoisted top-level install ("node_modules/<name>", exactly one
    # node_modules segment) over any nested copy, so a direct dependency's own
    # version wins regardless of dict ordering. Nested entries only fill names
    # that have no top-level install.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for top_level_only in (True, False):
            for path, entry in packages.items():
                if not path or not isinstance(entry, dict):
                    continue  # "" is the root project itself
                is_top_level = path.count("node_modules/") == 1
                if is_top_level != top_level_only:
                    continue
                # Take the package name as the final node_modules segment so
                # nested deps resolve to their own name, not their parent's path.
                name = path.split("node_modules/")[-1]
                version = entry.get("version")
                if name and isinstance(version, str) and name not in resolved:
                    resolved[name] = version

    # npm v6 ("lockfileVersion" 1): a nested "dependencies" tree.
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        _walk_v1_deps(deps, resolved)

    return resolved


def _walk_v1_deps(tree: dict, out: dict[str, str]) -> None:
    for name, entry in tree.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str) and name not in out:
            out[name] = version
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1_deps(nested, out)


def _resolved_from_pnpm(abspath: str) -> dict[str, str]:
    """Best-effort ``{name: version}`` from a pnpm-lock.yaml.

    Parsed without a YAML dependency by matching ``/name@version`` package keys
    under the ``packages:`` section. This is intentionally approximate; a proper
    pnpm resolver is a future extension.
    """
    resolved: dict[str, str] = {}
    try:
        with open(abspath, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return resolved
    # Keys look like "  /lodash@4.17.21:" or "  '/@scope/pkg@1.2.3':".
    for match in re.finditer(
        r"^\s+'?/?((?:@[^@/\s]+/)?[^@/\s]+)@([0-9][^:\s'()]*)", text, re.MULTILINE
    ):
        name, version = match.group(1), match.group(2)
        resolved.setdefault(name, version)
    return resolved


def _lockfile_versions(manifest_dir: str) -> dict[str, str]:
    package_lock = os.path.join(manifest_dir, "package-lock.json")
    if os.path.isfile(package_lock):
        return _resolved_from_package_lock(package_lock)
    pnpm_lock = os.path.join(manifest_dir, "pnpm-lock.yaml")
    if os.path.isfile(pnpm_lock):
        return _resolved_from_pnpm(pnpm_lock)
    return {}


@register
class JavaScriptManifestAdapter(ManifestAdapter):
    """Adapter for npm package.json manifests (with lockfile resolution)."""

    ecosystem = "npm"

    def matches(self, relpath: str) -> bool:
        return os.path.basename(relpath) == "package.json"

    def parse(self, abspath: str, relpath: str) -> list[Dependency]:
        data = _load_json(abspath)
        if not data:
            return []

        declared: dict[str, str] = {}
        for section in ("dependencies", "devDependencies"):
            block = data.get(section)
            if isinstance(block, dict):
                for name, spec in block.items():
                    if isinstance(name, str) and isinstance(spec, str):
                        declared.setdefault(name, spec)

        resolved = _lockfile_versions(os.path.dirname(abspath))

        deps: list[Dependency] = []
        for name, spec in declared.items():
            exact = resolved.get(name)
            if exact is not None:
                deps.append(
                    Dependency(name, exact, "npm", relpath, resolved=True, declared=spec)
                )
            else:
                deps.append(
                    Dependency(name, spec, "npm", relpath, resolved=False, declared=spec)
                )

        # Transitive dependencies: every package the lockfile resolved that the
        # manifest does NOT declare itself. These come straight from the fully
        # resolved tree (``_resolved_from_package_lock`` / ``_resolved_from_pnpm``
        # already enumerate the whole tree), so they are exact-version resolved.
        # They are ``direct=False`` -- the soundness key: a transitive dep is
        # never ruled unreachable. The root/self package and any empty entry are
        # skipped.
        self_name = data.get("name") if isinstance(data.get("name"), str) else None
        for name, version in resolved.items():
            if not name or not version or name in declared or name == self_name:
                continue
            deps.append(
                Dependency(
                    name, version, "npm", relpath, resolved=True, direct=False
                )
            )
        return deps
