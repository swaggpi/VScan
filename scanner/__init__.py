"""vscan scanner (layer 1).

A deterministic, offline pass that walks a target repository and builds a typed,
JSON-serializable knowledge graph of its structure: files, dependencies,
modules, functions, call edges, public entry points and documentation.

This layer performs NO vulnerability correlation and NO network I/O. Later
layers consume the graph to correlate dependencies against vulnerability data
and to reason about reachability.
"""

from __future__ import annotations

from .graph import Edge, KnowledgeGraph, Node
from .scan import scan_repo

__all__ = ["Edge", "KnowledgeGraph", "Node", "scan_repo"]
__version__ = "0.1.0"
