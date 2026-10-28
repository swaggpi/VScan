"""Shared infrastructure layer.

The leaf modules that actually call third-party dependencies: the YAML config
loader (PyYAML), the HTTP client (requests), the templating helper (Jinja2), a
tiny in-memory store, and a serializer. Services call into these; these call the
dependencies.
"""
