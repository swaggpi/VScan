# go-fiber-app — gofiber/fiber route + taint fixture

A minimal Go web app using `github.com/gofiber/fiber/v2` whose single route is
hand-verified for the Go analyzer's route detection and the sound taint pass.
Everything is offline: the `dep:Go:*` nodes, `calls` edges and resolved symbols
all come from the analyzer with no `go mod download`.

## Why fiber is interesting

fiber registers routes with verb methods (`app.Get`, `app.Post`, ...) exactly
like gin, once the router variable is bound from `fiber.New()`. The analyzer
tolerates the `/v2` module-version suffix on the import path. The handler
signature is `func(c *fiber.Ctx) error`, and `*fiber.Ctx` is a recognised
request-context taint source (`c.Query` / `c.Params` / `c.FormValue` / `c.Get`
/ `c.Body` / `c.Cookies`, plus the `c.BodyParser(&x)` bind).

## Dependencies

| module                        | why it is here                           |
| ----------------------------- | ---------------------------------------- |
| github.com/gofiber/fiber/v2   | the web framework (route + request source) |
| gopkg.in/yaml.v2              | the **positive** sink (`yaml.Unmarshal`) |

## Ground-truth route detection

| route          | framework | how detected                                                   |
| -------------- | --------- | -------------------------------------------------------------- |
| `POST /import` | `fiber`   | `app := fiber.New(); app.Post("/import", importHandler)` — the verb method `Post` on a fiber router emits `ep:POST:/import`. The handler `importHandler` resolves in-file. |

## Ground-truth taint

| route          | handler         | source        | sink             | verdict     | why |
| -------------- | --------------- | ------------- | ---------------- | ----------- | --- |
| `POST /import` | `importHandler` | `c.FormValue` | `yaml.Unmarshal` | **tainted** | `c.FormValue("data")` is passed to `parseYAML`, whose parameter flows (via `[]byte(...)`) straight into `yaml.Unmarshal`. Proven path: `ep:POST:/import -> importHandler -> parseYAML -> yaml`. |

## Dependency-level verdict (what `compute_taint` returns)

| dependency                 | verdict     | evidence                                                   |
| -------------------------- | ----------- | ---------------------------------------------------------- |
| `dep:Go:gopkg.in/yaml.v2`  | **tainted** | source `c.FormValue`, sink `yaml.Unmarshal`, via `/import` |
