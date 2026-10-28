# uv-app

A minimal **uv** sample that exercises `uv.lock` resolution for Python: PEP 621
`[project].dependencies` declares the direct deps, and the scanner resolves each
to its exact locked version from `uv.lock` (instead of the raw `>=`/`==`
constraint), then surfaces the rest of the resolved tree as transitive.

## Ground truth (hand-verified)

| package    | kind       | declared (`pyproject.toml`) | resolved version (`uv.lock`) | `direct` | `resolved` |
|------------|------------|-----------------------------|------------------------------|----------|------------|
| pyyaml     | **direct** | `pyyaml>=5.0` (unpinned)    | `5.4.1`                      | `True`   | `True`     |
| jinja2     | **direct** | `jinja2==3.1.2` (pinned)   | `3.1.2`                      | `True`   | `True`     |
| markupsafe | transitive | *(not named)*               | `2.1.5`                      | `False`  | `True`     |

- `pyyaml` is declared with a `>=` range -- **unpinned**, so OSV could not check
  it. `uv.lock` pins it to `5.4.1`; the scanner emits that exact version with
  `resolved=True`, no longer a `>=` constraint.
- `jinja2` is already `==`-pinned; resolution is harmless (same version `3.1.2`).
- `markupsafe` is jinja2's own dependency -- resolved only by `uv.lock`, never
  named in `pyproject.toml` -- so it becomes a `dependency` node with
  `direct=False`.
- The root project `uv-app` appears in its own `uv.lock` as a `[[package]]`; it
  is excluded by `[project].name` and emitted as neither direct nor transitive.

## Why it matters

Without `uv.lock` resolution a uv project's deps stay at their declared
constraints (`pyyaml>=5.0`), which OSV cannot range-check, so the pipeline finds
nothing. Resolving to `5.4.1` lets the vulnerability layer check a concrete
version.
