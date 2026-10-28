"""Business-logic layer.

Services sit between the HTTP blueprints in ``api/`` and the shared
infrastructure in ``core/``. They are plain module-level functions so the call
chain from a route to a dependency stays fully resolvable.
"""
