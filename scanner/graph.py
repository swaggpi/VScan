"""Knowledge-graph data model for the vscan scanner.

The scanner emits a typed, JSON-serializable graph describing the *structure* of
a target repository: its files, dependencies, modules, functions, public entry
points and documentation, plus the edges between them (imports, calls, route
wiring, documentation links, containment).

Nothing in this module performs analysis or I/O. It is a pure in-memory model
with deterministic serialization so the output is stable across runs and easy to
diff and to feed into later layers (vulnerability correlation and reachability).

Node id conventions (kept consistent across the whole scanner):

* ``dep:<ecosystem>:<name>``   -- a declared dependency
* ``file:<relpath>``           -- a file in the repository
* ``mod:<module.path>``        -- an importable module
* ``fn:<relpath>:<qualname>``  -- a function or method
* ``ep:<METHOD>:<path>``       -- a public entry point (route)
* ``doc:<relpath>``            -- a documentation file
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Allowed node kinds. Kept as a frozenset so callers can validate against it.
NODE_KINDS: frozenset[str] = frozenset(
    {"file", "module", "dependency", "function", "entrypoint", "doc"}
)

# Allowed edge kinds.
EDGE_KINDS: frozenset[str] = frozenset(
    {"imports", "calls", "declares", "route_to_handler", "documents", "contains"}
)


@dataclass
class Node:
    """A single vertex in the knowledge graph.

    ``id`` is stable and unique (see the id conventions in the module docstring).
    ``attrs`` is a free-form, JSON-serializable dict of extra facts about the
    node (line numbers, versions, excerpts, ...).
    """

    id: str
    kind: str
    name: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "name": self.name, "attrs": self.attrs}


@dataclass
class Edge:
    """A directed relationship between two nodes, referenced by id."""

    src: str
    dst: str
    kind: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind, "attrs": self.attrs}


class KnowledgeGraph:
    """A collection of :class:`Node` and :class:`Edge` objects.

    Nodes are de-duplicated by id (re-adding merges ``attrs``). Edges are
    de-duplicated by their ``(src, dst, kind, symbol)`` signature so that two
    genuinely different calls between the same pair of nodes are both kept, while
    identical edges are collapsed.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []
        self._edge_keys: set[tuple[str, str, str, str]] = set()

    # -- construction ---------------------------------------------------------

    def add_node(self, id: str, kind: str, name: str, **attrs: Any) -> Node:
        """Add a node, or merge ``attrs`` into an existing node with the same id.

        Returns the stored node either way, so callers can keep building on it.
        """
        existing = self._nodes.get(id)
        if existing is not None:
            if attrs:
                existing.attrs.update(attrs)
            return existing
        node = Node(id=id, kind=kind, name=name, attrs=dict(attrs))
        self._nodes[id] = node
        return node

    def add_edge(self, src: str, dst: str, kind: str, **attrs: Any) -> Edge | None:
        """Add a directed edge, de-duplicating identical edges.

        The de-dup signature includes ``attrs['symbol']`` (if present) so that,
        for example, ``yaml.load`` and ``yaml.safe_load`` calls from the same
        function to the same dependency are not collapsed into one edge.
        """
        key = (src, dst, kind, str(attrs.get("symbol", "")))
        if key in self._edge_keys:
            return None
        self._edge_keys.add(key)
        edge = Edge(src=src, dst=dst, kind=kind, attrs=dict(attrs))
        self._edges.append(edge)
        return edge

    # -- access ---------------------------------------------------------------

    def has_node(self, id: str) -> bool:
        return id in self._nodes

    def get_node(self, id: str) -> Node | None:
        return self._nodes.get(id)

    @property
    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges)

    def nodes_of_kind(self, kind: str) -> list[Node]:
        return [n for n in self._nodes.values() if n.kind == kind]

    # -- serialization --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable representation."""
        nodes = [n.to_dict() for n in sorted(self._nodes.values(), key=lambda n: n.id)]
        edges = [
            e.to_dict()
            for e in sorted(
                self._edges,
                key=lambda e: (e.kind, e.src, e.dst, str(e.attrs.get("symbol", ""))),
            )
        ]
        return {"version": 1, "nodes": nodes, "edges": edges, "summary": self.summary()}

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def summary(self) -> dict[str, Any]:
        """Return counts per node kind, per edge kind, and the dependency list."""
        node_counts: dict[str, int] = {}
        for node in self._nodes.values():
            node_counts[node.kind] = node_counts.get(node.kind, 0) + 1

        edge_counts: dict[str, int] = {}
        for edge in self._edges:
            edge_counts[edge.kind] = edge_counts.get(edge.kind, 0) + 1

        dependencies = []
        for node in self.nodes_of_kind("dependency"):
            dependencies.append(
                {
                    "name": node.name,
                    "ecosystem": node.attrs.get("ecosystem"),
                    "version": node.attrs.get("version"),
                    "resolved": node.attrs.get("resolved", False),
                    "source_file": node.attrs.get("source_file"),
                }
            )
        dependencies.sort(key=lambda d: (str(d["ecosystem"]), str(d["name"])))

        return {
            "node_counts": dict(sorted(node_counts.items())),
            "edge_counts": dict(sorted(edge_counts.items())),
            "dependencies": dependencies,
        }
