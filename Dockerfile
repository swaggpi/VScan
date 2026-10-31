FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 1000 vscan

WORKDIR /app
COPY pyproject.toml README.md ./
COPY scanner ./scanner
RUN pip install ".[mcp]"

# Repositories to scan are mounted here; relative repo_path values resolve here.
WORKDIR /repos
USER vscan

EXPOSE 8000
CMD ["vscan-mcp", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
