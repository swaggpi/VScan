"""HTTP layer: one Flask blueprint per feature area.

Every route handler here is a plain, named module-level function so the
reachability engine can resolve the route -> handler edge and then follow the
call chain down through ``services/`` and ``core/``.
"""
