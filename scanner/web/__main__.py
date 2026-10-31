"""``python -m scanner.web`` / ``vscan-web`` entry point.

Runs the FastAPI app (:data:`scanner.web.app.app`) under uvicorn, binding
``0.0.0.0`` on the port from env ``PORT`` (default ``8000``).
"""

from __future__ import annotations

import os


def main() -> None:
    """Console entry point: serve the vscan web app over HTTP."""
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("scanner.web.app:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
