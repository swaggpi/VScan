"""Starlette (ASGI) demo app exercising route-LIST detection + taint.

Starlette declares routes as a LIST of ``Route``/``Mount`` objects bound on the
``Starlette(routes=...)`` application -- there are no route decorators. See
README.md for the ground truth (routes + which dependency is reachable/tainted).
"""

from starlette.applications import Starlette
from starlette.routing import Mount, Route

from config import load_config


async def import_endpoint(request):
    """TAINTED: attacker-controlled JSON body flows into the PyYAML sink.

    ``await request.json()`` is an awaited Starlette source; it is passed
    cross-file into ``config.load_config`` -> ``yaml.load``.
    """
    data = await request.json()
    config = load_config(data)
    return {"loaded": bool(config)}


async def user_endpoint(request):
    """Default-GET route; reads a path-param source but reaches no sink."""
    uid = request.path_params["id"]
    return {"user": uid}


async def items_endpoint(request):
    """Mounted under ``/api`` -> GET /api/items. No dependency sink."""
    return {"items": []}


# Module-level route list passed to ``Starlette(routes=routes)`` (also valid
# inline as ``Starlette(routes=[...])``).
routes = [
    Route("/import", import_endpoint, methods=["POST"]),
    Route("/user/{id}", user_endpoint),  # GET by default
    Mount("/api", routes=[Route("/items", items_endpoint)]),  # prefix composition
]

app = Starlette(routes=routes)
