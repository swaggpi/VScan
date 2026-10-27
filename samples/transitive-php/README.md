# transitive-php

A minimal Composer sample that exercises **transitive dependency** scanning for
PHP: the scanner surfaces packages from the whole resolved `composer.lock` tree,
not just the ones `composer.json` declares -- while keeping reachability **sound**.

## Ground truth (hand-verified)

| package         | kind       | source                              | `direct` |
|-----------------|------------|-------------------------------------|----------|
| monolog/monolog | **direct** | declared in `composer.json` require | `True`   |
| psr/log         | transitive | resolved only by `composer.lock`    | `False`  |

`composer.json` requires exactly one Packagist package (`monolog/monolog`); the
`php` platform requirement is filtered out (not a Packagist package).
`composer.lock` resolves `psr/log` as well -- a package the manifest never names
-- so it becomes a `dependency` node with `direct=False`. Platform entries in
the lock (`php`, `ext-*`) are filtered the same way.

## Reachability ground truth (the soundness crux)

`routes.php` wires `GET /health` to a handler whose body makes **no calls**, so
the reachable region is **fully resolved**. Neither dep has an incoming call
edge. The verdicts are therefore:

| package         | verdict                 | why                                                       |
|-----------------|-------------------------|-----------------------------------------------------------|
| monolog/monolog | `unreachable`           | direct dep, no call edge, region fully resolved           |
| psr/log         | `potentially_reachable` | transitive: a reachable top-level dep *might* reach it    |

Same region, same edge-absence -- the only thing that differs is the `direct`
flag. A transitive dep must **never** be marked `unreachable`: we do not analyze
a top-level dependency's internals, so the honest verdict is
`potentially_reachable`.
