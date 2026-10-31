"""Service layer: business logic the routes delegate into.

Services orchestrate the core infrastructure (store, serializer, logging,
outbound HTTP) and are the middle of every call chain between a route and the
dependency it ultimately uses.
"""
