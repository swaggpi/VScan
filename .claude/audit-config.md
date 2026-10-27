# Audit configuration
Detected 2026-10-27. Edit freely; this file is authoritative on later runs.

- base_branch: main
- lint: ./.venv/bin/python -m ruff check scanner tests
- typecheck: (none configured; no mypy/pyright) — UNVERIFIED
- format: (none configured)
- test: ./.venv/bin/python -m pytest -q
- test_paths: tests/
- report_dir: .claude/audit/
- docs: README.md, PLAN.md, MORNING.md
- exclude: .venv/, __pycache__/, test-corpus/, .research/, samples/, dashboard/*-bundle.json
