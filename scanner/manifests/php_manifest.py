"""PHP manifest adapter (DEEP): composer.json + composer.lock.

Emits Packagist dependencies. Declared versions come from ``require`` and
``require-dev`` in ``composer.json``. When a sibling ``composer.lock`` is
present its ``packages`` + ``packages-dev`` arrays are enumerated and every
locked package the manifest does not declare itself is emitted as
``direct=False`` (the soundness key: a transitive dep is never ruled
unreachable). Platform requirements (``php``, ``ext-*``, ...) are filtered out
of both the declared and the resolved sets.
"""

from __future__ import annotations

import json
import os

from . import Dependency, ManifestAdapter, register

# Platform requirements that appear in ``require`` but are not Packagist
# packages (the PHP runtime itself and its extensions).
def _is_platform_requirement(name: str) -> bool:
    lower = name.lower()
    return lower == "php" or lower.startswith(("php-", "ext-", "lib-")) or "/" not in name


def _sibling_relpath(manifest_relpath: str, filename: str) -> str:
    """Repo-relative path of ``filename`` next to ``manifest_relpath``."""
    directory = os.path.dirname(manifest_relpath)
    return f"{directory}/{filename}" if directory else filename


def _transitive_from_composer_lock(
    manifest_abspath: str, manifest_relpath: str, declared: set[str]
) -> list[Dependency]:
    """Enumerate a sibling ``composer.lock``, minus the declared packages.

    ``packages`` + ``packages-dev`` each hold objects with a ``name`` and a
    resolved ``version`` (kept verbatim, consistent with how the declared path
    keeps composer version strings). Every locked, non-platform package the
    manifest does not declare is emitted as ``direct=False``. Missing/malformed
    lock files yield nothing rather than raising.
    """
    lock_abspath = os.path.join(os.path.dirname(manifest_abspath), "composer.lock")
    if not os.path.isfile(lock_abspath):
        return []
    lock_relpath = _sibling_relpath(manifest_relpath, "composer.lock")
    try:
        with open(lock_abspath, encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[Dependency] = []
    seen: set[str] = set()
    for section in ("packages", "packages-dev"):
        arr = data.get(section)
        if not isinstance(arr, list):
            continue
        for pkg in arr:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not isinstance(name, str) or _is_platform_requirement(name):
                continue
            if name in declared or name in seen:
                continue
            seen.add(name)
            version = pkg.get("version")
            version = version.strip() if isinstance(version, str) and version.strip() else "*"
            out.append(
                Dependency(name, version, "Packagist", lock_relpath, resolved=True, direct=False)
            )
    return out


@register
class PhpManifestAdapter(ManifestAdapter):
    """Adapter for composer.json manifests (with composer.lock resolution)."""

    ecosystem = "Packagist"

    def matches(self, relpath: str) -> bool:
        return os.path.basename(relpath) == "composer.json"

    def parse(self, abspath: str, relpath: str) -> list[Dependency]:
        try:
            with open(abspath, encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []

        deps: list[Dependency] = []
        declared: set[str] = set()
        for section in ("require", "require-dev"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, spec in block.items():
                if not isinstance(name, str) or _is_platform_requirement(name):
                    continue
                version = spec.strip() if isinstance(spec, str) else "*"
                deps.append(
                    Dependency(
                        name,
                        version or "*",
                        "Packagist",
                        relpath,
                        resolved=False,
                        declared=version or "*",
                    )
                )
                declared.add(name)

        # Transitive deps from the sibling composer.lock (every locked package
        # the manifest does not declare itself), direct=False -- the soundness
        # key: a transitive dep is never ruled unreachable.
        deps.extend(_transitive_from_composer_lock(abspath, relpath, declared))
        return deps
