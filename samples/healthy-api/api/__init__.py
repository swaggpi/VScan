"""HTTP layer: one FastAPI router per feature area.

Routers are included on the application in ``app.py``. Every handler is a plain,
named module-level function so the reachability engine resolves the
route -> handler edge and then follows the call chain down through ``services/``
and ``core/``.
"""
