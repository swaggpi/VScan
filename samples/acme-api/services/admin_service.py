"""Admin service -- reaches the YAML loader with a constant default config.

``effective_config`` parses a bundled default-config string through the same
``config_loader`` the flagship import path uses. Because the parsed text is a
fixed constant (not request data), this path reaches PyYAML without tainting it.
"""

from core import config_loader, db

# The service's built-in default configuration, shipped with the app. Parsing a
# constant here is what makes PyYAML reachable from /admin/config WITHOUT taint.
_DEFAULT_CONFIG = """
retention_days: 30
max_document_bytes: 1048576
features:
  reports: true
  webhooks: true
"""


def status_report():
    """Return simple service status counters."""
    return {
        "documents": len(db.document_ids()),
        "reports": len(db.report_ids()),
        "healthy": True,
    }


def effective_config():
    """Return the effective configuration, parsed from the bundled default."""
    return config_loader.load_spec(_DEFAULT_CONFIG)
