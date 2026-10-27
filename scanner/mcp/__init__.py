"""MCP server package exposing the vulnreach scanner as AI tools.

The server (``scanner.mcp.server``) wraps the vulnreach library in process and
speaks MCP over stdio. Run it with the ``vulnreach-mcp`` console script or
``python -m scanner.mcp``.

``mcp`` is an optional dependency; importing :func:`main` lazily keeps the core
package importable without it.
"""

from __future__ import annotations

__all__ = ["main"]


def main(argv: list[str] | None = None) -> None:
    """Entry point shim; imports the server lazily so core stays dep-free."""
    from .server import main as _main

    _main(argv)
