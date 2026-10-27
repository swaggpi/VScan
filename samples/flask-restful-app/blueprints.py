"""A Flask Blueprint whose ``url_prefix`` must be composed onto its routes.

``widgets_bp`` carries ``url_prefix="/api/v1"`` at construction, so the decorated
route ``/widgets`` resolves to the full path ``/api/v1/widgets``. ``health_view``
is a plain function wired imperatively from :mod:`app` via ``add_url_rule``.
"""

from flask import Blueprint

widgets_bp = Blueprint("widgets", __name__, url_prefix="/api/v1")


@widgets_bp.route("/widgets")
def list_widgets():
    return []


def health_view():
    return "ok"
