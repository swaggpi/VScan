"""Manifest adapters: the extensibility seam for dependency extraction.

Each supported packaging ecosystem is handled by a :class:`ManifestAdapter`.
An adapter knows how to recognise its manifest files (``matches``) and how to
turn one into a list of :class:`Dependency` records (``parse``).

Adding a new ecosystem later is deliberately a closed, well-defined operation:

1. Write a module in this package with a subclass of :class:`ManifestAdapter`.
2. Decorate the class with :func:`register` (or append an instance to
   ``REGISTRY``).
3. Import the module below so the registry is populated at import time.

``scan.py`` never names a concrete adapter -- it only calls
:func:`adapter_for`. That indirection is the seam: future ecosystems plug in
here without touching the orchestrator, the graph model or the walker.

This layer is intentionally offline: adapters read declared and (where a
lockfile is present) resolved versions straight from files. They never reach
the network and never consult vulnerability data -- that is a later layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# The four ecosystems understood in this layer. Stored as a constant so other
# modules (and tests) can refer to the canonical spelling.
ECOSYSTEMS: frozenset[str] = frozenset({"PyPI", "npm", "Packagist", "Go"})


@dataclass
class Dependency:
    """A single declared dependency.

    ``version`` holds the resolved version when one was available (e.g. from a
    lockfile) and otherwise the declared constraint. ``resolved`` records which
    of the two it is, so later layers know how much to trust the version.
    ``declared`` always preserves the original spec from the manifest.
    """

    name: str
    version: str
    ecosystem: str
    source_file: str  # repo-relative path of the manifest the dep came from
    resolved: bool = False
    declared: str | None = None

    def node_id(self) -> str:
        return f"dep:{self.ecosystem}:{self.name}"


class ManifestAdapter:
    """Base interface for a dependency-manifest adapter.

    Subclasses set :attr:`ecosystem` and implement :meth:`matches` and
    :meth:`parse`. Adapters must be pure and offline.
    """

    #: The canonical ecosystem name this adapter emits (see :data:`ECOSYSTEMS`).
    ecosystem: str = ""

    def matches(self, relpath: str) -> bool:
        """Return ``True`` if this adapter can parse the file at ``relpath``."""
        raise NotImplementedError

    def parse(self, abspath: str, relpath: str) -> list[Dependency]:
        """Parse the manifest at ``abspath`` into a list of dependencies.

        Implementations must not raise on malformed input: return the
        dependencies that could be parsed and skip the rest.
        """
        raise NotImplementedError


# The registry. Order matters only in that the first matching adapter wins.
REGISTRY: list[ManifestAdapter] = []


def register(cls: type[ManifestAdapter]) -> type[ManifestAdapter]:
    """Class decorator that registers a single instance of ``cls``."""
    REGISTRY.append(cls())
    return cls


def adapter_for(relpath: str) -> ManifestAdapter | None:
    """Return the first registered adapter that matches ``relpath``, if any."""
    for adapter in REGISTRY:
        if adapter.matches(relpath):
            return adapter
    return None


# Importing the concrete adapters populates REGISTRY. Kept at the bottom to
# avoid a circular import (the adapters import names defined above).
from . import go_manifest  # noqa: E402,F401
from . import javascript_manifest  # noqa: E402,F401
from . import php_manifest  # noqa: E402,F401
from . import python_manifest  # noqa: E402,F401
