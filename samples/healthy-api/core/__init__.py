"""Core infrastructure shared across the service.

Small, single-purpose modules the services lean on: configuration, the in-memory
store, JSON serialization (orjson), structured logging (structlog), and the
outbound HTTP client lives one layer up in ``services.link_service``.
"""
