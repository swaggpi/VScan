# vscan web backend image.
#
# Build context is the repository ROOT (so the package and the bundled sample
# repos are available to COPY):
#
#   docker build -t vscan-backend -f deploy/web/Dockerfile .
#
# No secrets are baked in. The provider-neutral LLM_* configuration (and any
# NVD_API_KEY) is injected at `docker run` time via --env-file, never here.
FROM python:3.12-slim

# Keep Python lean and logs unbuffered for container stdout.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy the whole repo (package sources + samples/acme-api, which the service
# scans on startup) and install the package with its runtime deps, including
# the web extras (fastapi + uvicorn[standard]) and the ``mcp`` extra (FastMCP),
# which the /api/chat agent needs to expose the vscan tools to the model.
# tree_sitter_language_pack is a normal pip wheel, so no system toolchain is
# needed.
COPY . /app
RUN pip install ".[mcp]"

# The demo repos the service warms on startup resolve to these in-container
# paths. ``VSCAN_DEMO_REPOS`` (comma-separated) warms both, with acme-api first
# so it stays the PRIMARY (what /api/health reports and the no-param
# /api/enrichment serves); plugin-reports is the secondary demo scan.
# ``VSCAN_DEMO_REPO`` is kept as the single-repo fallback (acme-api) but is
# overridden by ``VSCAN_DEMO_REPOS`` when both are set. All overridable via env.
ENV VSCAN_DEMO_REPOS="/app/samples/acme-api,/app/samples/plugin-reports" \
    VSCAN_DEMO_REPO=/app/samples/acme-api \
    PORT=8000

EXPOSE 8000

# vscan-web binds 0.0.0.0 on $PORT and runs scanner.web.app:app under uvicorn.
CMD ["vscan-web"]
