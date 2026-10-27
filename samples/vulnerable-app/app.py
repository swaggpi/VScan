"""Demo application: a tiny Flask service used to exercise the scanner.

It exposes a public upload endpoint that flows user input into a configuration
loader, plus a health check. There is nothing malicious here -- it simply pins
old dependencies and has a clear, resolvable call chain.
"""

from flask import Flask, jsonify, request

from utils.config_loader import load_config

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_data():
    """Public endpoint: accept a configuration upload and load it."""
    raw = request.get_data(as_text=True)
    config = load_config(raw)
    return jsonify({"loaded": bool(config)})


@app.route("/health")
def health():
    """Liveness probe."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run()
