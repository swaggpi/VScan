"""PHP manifest adapter (THIN): composer.json.

Emits Packagist dependencies with their *declared* versions from ``require``
and ``require-dev``. Lockfile (``composer.lock``) resolution is a future
extension; this adapter is deliberately shallow.
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


@register
class PhpManifestAdapter(ManifestAdapter):
    """Adapter for composer.json manifests."""

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
        return deps
