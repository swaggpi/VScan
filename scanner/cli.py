"""Command-line interface: ``vulnreach scan`` and ``vulnreach reachability``.

``scan`` builds the knowledge graph for a target repository, writes it as JSON,
and prints a human-readable summary to stderr. ``reachability`` builds the same
graph, computes which public entry points reach which functions and
dependencies, and prints a readable report (or JSON).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .graph import KnowledgeGraph
from .reachability import ReachabilityResult, compute_reachability
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


def _format_reachability(result: ReachabilityResult, repo_path: str) -> str:
    """Render a reachability result as a human-readable text report."""
    lines: list[str] = []
    lines.append(f"vulnreach reachability: {repo_path}")
    lines.append("")

    if not result.entrypoints:
        lines.append("No public entry points found.")
    for ep in result.entrypoints:
        handlers = ", ".join(ep.handlers) if ep.handlers else "(no resolved handler)"
        lines.append(f"{ep.method} {ep.path} -> {handlers}")
        lines.append(f"  reachable functions: {ep.reachable_function_count}")
        if ep.reachable_dependencies:
            lines.append("  reachable dependencies:")
            for dep in ep.reachable_dependencies:
                symbol = dep.symbol or "?"
                lines.append(
                    f"    - {dep.name} {dep.version} [{dep.ecosystem}]  "
                    f"(called via {symbol})"
                )
                lines.append(f"      example path: {' -> '.join(dep.example_path)}")
        else:
            lines.append("  reachable dependencies: none")
        lines.append(
            f"  unresolved calls encountered: {ep.unresolved_calls_encountered} "
            "(reachability is a lower bound -- unresolved call sites are never "
            "turned into edges)"
        )
        lines.append("")

    repo = result.repo
    lines.append("Dependencies reachable from a public entry point:")
    if repo.reachable_deps:
        for dep in repo.reachable_deps:
            lines.append(
                f"  - {dep['name']} {dep['version']} [{dep['ecosystem']}]"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("Declared but not reachable from any entry point:")
    if repo.unreachable_deps:
        no_call_site = {d["id"] for d in repo.deps_without_call_site}
        for dep in repo.unreachable_deps:
            note = " (no resolved call site at all)" if dep["id"] in no_call_site else ""
            lines.append(
                f"  - {dep['name']} {dep['version']} [{dep['ecosystem']}]{note}"
            )
    else:
        lines.append("  (none)")

    return "\n".join(lines)


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

    reach_parser = subparsers.add_parser(
        "reachability",
        help="Compute which entry points reach which functions and dependencies.",
    )
    reach_parser.add_argument("repo_path", help="Path to the repository to scan.")
    reach_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path to write the full reachability result as JSON.",
    )
    reach_parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to stdout instead of the text report.",
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

    if args.command == "reachability":
        try:
            graph = scan_repo(args.repo_path)
        except (NotADirectoryError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        result = compute_reachability(graph)
        payload = json.dumps(result.to_dict(), indent=2)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(payload)

        if args.json:
            print(payload)
        else:
            print(_format_reachability(result, args.repo_path))
        return 0

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
