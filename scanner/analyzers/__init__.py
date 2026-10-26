"""Per-language code analyzers.

An analyzer turns a source file into graph structure: module and function
nodes, import edges, call edges, and public entry points (routes).

Python is analyzed *deeply* (full stdlib-``ast`` analysis with cross-file call
resolution). JavaScript, PHP and Go have single-file analyzers over the same
:class:`LanguageAnalyzer` seam. Absence of an analyzer for a language is handled
gracefully by the orchestrator (the file still appears as a ``file`` node from
the walker; it simply gets no code-level structure).
"""

from __future__ import annotations

from typing import Any


class LanguageAnalyzer:
    """Base interface for a language code analyzer.

    Subclasses set :attr:`language` and implement :meth:`analyze`.
    """

    #: The walker language string this analyzer handles (e.g. ``"python"``).
    language: str = ""

    def analyze(
        self,
        file_node: Any,
        source: str,
        graph: Any,
        repo_index: dict[str, Any],
    ) -> None:
        """Analyse one file and add nodes/edges to ``graph``.

        ``file_node`` is the file's :class:`~scanner.graph.Node`; ``source`` is
        its text; ``repo_index`` is the shared cross-file index built by
        :mod:`scanner.scan` (module map, function map, import->dependency map),
        which lets an analyzer resolve references into other files.
        """
        raise NotImplementedError


# language -> analyzer instance.
REGISTRY: dict[str, LanguageAnalyzer] = {}


def register(cls: type[LanguageAnalyzer]) -> type[LanguageAnalyzer]:
    instance = cls()
    REGISTRY[instance.language] = instance
    return cls


def analyzer_for(language: str) -> LanguageAnalyzer | None:
    """Return the analyzer for ``language``, or ``None`` if none is registered."""
    return REGISTRY.get(language)


# Importing concrete analyzers populates REGISTRY. Python is analyzed deeply;
# JavaScript, PHP and Go are single-file analyzers over the same seam.
from . import python_analyzer  # noqa: E402,F401
from . import javascript_analyzer  # noqa: E402,F401
from . import php_analyzer  # noqa: E402,F401
from . import go_analyzer  # noqa: E402,F401
