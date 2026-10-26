"""Go manifest adapter (THIN): go.mod.

Emits Go module dependencies with their declared versions from the ``require``
directives (both the single-line form and the grouped ``require ( ... )``
block). ``go.sum`` carries checksums rather than a different version resolution,
so it is not consulted here.
"""

from __future__ import annotations

import os
import re

from . import Dependency, ManifestAdapter, register

# A "module version" pair on a require line, e.g. "github.com/foo/bar v1.2.3".
_REQUIRE_PAIR = re.compile(r"^(?P<module>[^\s]+)\s+(?P<version>v[^\s/]+)")


@register
class GoManifestAdapter(ManifestAdapter):
    """Adapter for go.mod files."""

    ecosystem = "Go"

    def matches(self, relpath: str) -> bool:
        return os.path.basename(relpath) == "go.mod"

    def parse(self, abspath: str, relpath: str) -> list[Dependency]:
        try:
            with open(abspath, encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError:
            return []

        deps: list[Dependency] = []
        in_block = False
        for raw in lines:
            line = raw.split("//", 1)[0].strip()  # drop comments
            if not line:
                continue
            if line.startswith("require") and "(" in line:
                in_block = True
                # Handle "require ( module v1 )" written inline (rare) too.
                tail = line.split("(", 1)[1].strip()
                if tail:
                    self._add_pair(tail, relpath, deps)
                continue
            if in_block:
                if line.startswith(")"):
                    in_block = False
                    continue
                self._add_pair(line, relpath, deps)
                continue
            if line.startswith("require "):
                self._add_pair(line[len("require ") :].strip(), relpath, deps)
        return deps

    @staticmethod
    def _add_pair(text: str, relpath: str, deps: list[Dependency]) -> None:
        match = _REQUIRE_PAIR.match(text)
        if not match:
            return
        deps.append(
            Dependency(
                match.group("module"),
                match.group("version"),
                "Go",
                relpath,
                resolved=False,
                declared=match.group("version"),
            )
        )
