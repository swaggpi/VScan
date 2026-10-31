"""Document blueprint -- the flagship attack surface.

``POST /documents/import`` is the one genuinely exploitable route in the app.
It reads the raw request body and hands it, unchanged, to the document service,
which carries it down through the config loader and into ``yaml.load`` -- an
unsafe PyYAML deserialization sink. The attacker-controlled body threads through
every hop as a plain function argument, so the taint pass can prove the flow end
to end:

    POST /documents/import
      -> document_service.ingest(payload)        # api -> services
      -> document_service.build_spec(payload)    # services (sibling)
      -> config_loader.load_spec(spec)           # services -> core
      -> config_loader.parse_yaml(text)          # core (sibling)
      -> yaml.full_load(text)                     # core -> PyYAML  (SINK)

The ``GET`` routes are read-only and reach no vulnerable sink; they exist so the
blueprint has realistic breadth.
"""

from flask import Blueprint, jsonify, request

from services import document_service

bp = Blueprint("documents", __name__)


@bp.route("/documents/import", methods=["POST"])
def import_document():
    """Public route: import a document spec supplied as a YAML/JSON body.

    FLAGSHIP: the request body is attacker-controlled and flows, unmodified,
    into the PyYAML sink several hops below.
    """
    payload = request.get_data(as_text=True)
    document_id = document_service.ingest(payload)
    return jsonify({"imported": document_id})


@bp.route("/documents/<document_id>", methods=["GET"])
def get_document(document_id):
    """Public route: fetch a previously imported document by id."""
    document = document_service.fetch(document_id)
    return jsonify({"document": document})


@bp.route("/documents", methods=["GET"])
def list_documents():
    """Public route: list the ids of all imported documents."""
    return jsonify({"documents": document_service.list_ids()})
