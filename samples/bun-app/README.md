# bun-app

A minimal **bun** sample that exercises `bun.lock` resolution for JavaScript.
`bun.lock` is JSONC (standard JSON plus trailing commas), so the scanner cleans
it before parsing. `package.json` declares the direct dep; `bun.lock` resolves
it to an exact version and surfaces the rest of the tree as transitive.

## Ground truth (hand-verified)

| package | kind       | declared (`package.json`) | resolved version (`bun.lock`) | `direct` | `resolved` |
|---------|------------|---------------------------|-------------------------------|----------|------------|
| express | **direct** | `^4.18.0` (range)         | `4.18.2`                      | `True`   | `True`     |
| accepts | transitive | *(not named)*             | `1.3.8`                       | `False`  | `True`     |

- `express` is declared with a caret range `^4.18.0`; `bun.lock` resolves it to
  the exact version `4.18.2`, emitted with `resolved=True` (not the range).
- `accepts` is express's own dependency -- resolved only by `bun.lock`, never
  named in `package.json` -- so it becomes a `dependency` node with
  `direct=False`.
- `bun.lock` uses trailing commas (JSONC). The reader strips them (and any
  full-line `//` comments) before `json.loads`; the real ehl-bmw bun.lock files
  round-trip through the same cleanup.

## Why it matters

Without `bun.lock` resolution a bun project's deps stay at their declared ranges
(`^4.18.0`), which OSV cannot check, so the pipeline finds nothing. Resolving to
`4.18.2` lets the vulnerability layer check a concrete version.
