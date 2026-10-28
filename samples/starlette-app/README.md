# starlette-app

A small Starlette (ASGI) target for the vulnreach scanner. Starlette declares
routes as a **list** of `Route`/`Mount` objects bound on the application
(`Starlette(routes=...)`) rather than with decorators, so this fixture exercises
the scanner's route-LIST detection and `Mount` prefix composition.

## Entry points (ground truth)

| Method | Path          | Handler                    | Framework |
|--------|---------------|----------------------------|-----------|
| POST   | `/import`     | `app.py:import_endpoint`   | starlette |
| GET    | `/user/{id}`  | `app.py:user_endpoint`     | starlette |
| GET    | `/api/items`  | `app.py:items_endpoint`    | starlette |

- `/import` is declared `methods=["POST"]` -> emitted as `ep:POST:/import`.
- `/user/{id}` has no `methods=` -> defaults to GET (Starlette default).
- `/api/items` comes from `Mount("/api", routes=[Route("/items", ...)])` -> the
  `/api` prefix composes onto `/items` giving `ep:GET:/api/items`.

## Dependency reachability + taint (ground truth)

- **PyYAML** is **reachable** and **tainted**.
  - Source: `request.json` (`data = await request.json()` in `import_endpoint`).
  - Sink: `yaml.load` (in `config.load_config`).
  - Path: `ep:POST:/import` -> `app.py:import_endpoint` ->
    `config.py:load_config` -> `dep:PyPI:PyYAML`.

The GET routes read request sources (`request.path_params`) but reach no
dependency sink, so they introduce no tainted flow.
