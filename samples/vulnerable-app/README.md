# demo app

A small, multi-ecosystem demo target for the VScan scanner. It pins old
dependencies on purpose and keeps a short, resolvable call chain.

## Endpoints

The `/import` endpoint accepts uploads from any user and passes the body into
`load_config`, which parses it as YAML. The `/health` endpoint is a simple
liveness probe.
