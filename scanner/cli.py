"""Command-line interface: ``vulnreach scan <repo> [-o out.json]``.

Builds the knowledge graph for a target repository, writes it as JSON, and
prints a human-readable summary to stderr.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from .graph import KnowledgeGraph
from .scan import scan_repo

_DEFAULT_OUTPUT = "vulnreach-graph.json"


def _print_summary(graph: KnowledgeGraph, repo_path: str, output_path: str) -> None:
    summary = graph.summary()
    node_counts = summary["node_counts"]
    deps = summary["dependencies"]

    out = sys.stderr
    print(f"vulnreach scan: {repo_path}", file=out)
    print(f"  files:        {node_counts.get('file', 0)}", file=out)
    print(f"  modules:      {node_counts.get('module', 0)}", file=out)
    print(f"  functions:    {node_counts.get('function', 0)}", file=out)
    print(f"  entrypoints:  {node_counts.get('entrypoint', 0)}", file=out)
    print(f"  docs:         {node_counts.get('doc', 0)}", file=out)
    print(f"  dependencies: {len(deps)}", file=out)

    if deps:
        print("\n  Dependencies:", file=out)
        for dep in deps:
            marker = "resolved" if dep["resolved"] else "declared"
            print(
                f"    - [{dep['ecosystem']}] {dep['name']} "
                f"{dep['version']} ({marker})",
                file=out,
            )

    entrypoints = graph.nodes_of_kind("entrypoint")
    if entrypoints:
        print("\n  Entry points:", file=out)
        for ep in sorted(entrypoints, key=lambda n: n.id):
            handler = ep.attrs.get("handler", "?")
            print(
                f"    - {ep.attrs.get('method', '?')} {ep.attrs.get('path', '?')} "
                f"-> {handler}",
                file=out,
            )

    print(f"\n  Graph written to: {output_path}", file=out)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnreach",
        description="Reachability-aware dependency scanner (layer 1: structure graph).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="Scan a repository and emit its knowledge graph as JSON."
    )
    scan_parser.add_argument("repo_path", help="Path to the repository to scan.")
    scan_parser.add_argument(
        "-o",
        "--output",
        default=_DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {_DEFAULT_OUTPUT}).",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            graph = scan_repo(args.repo_path)
        except (NotADirectoryError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(graph.to_json())

        _print_summary(graph, args.repo_path, args.output)
        return 0

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
