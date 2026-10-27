"""Code that is NOT wired to any HTTP route, plus unresolvable-by-design calls.

Nothing here is reachable from a public entry point, which is itself part of the
ground truth:

  * ``sync`` calls into urllib3, but no route reaches ``sync`` -> urllib3 is a
    declared, vulnerable, UNREACHABLE dependency.
  * ``click`` is imported but never called -> an imported-only dependency (no
    ``calls`` edge), must not be reported as reached.
  * ``run_plugin`` loads a module BY NAME at runtime. The target is unknowable
    statically, so the analyzer must record it as unresolved and MUST NOT
    fabricate a call edge to any function or dependency.

Kept in its own non-routed module so these unresolved/dynamic calls never taint
the reachable region, letting the route->handler->dep chains resolve cleanly.
"""

from __future__ import annotations

import importlib

import click
import urllib3

from store import Store


def bootstrap():
    # Exercises the Store method chain OFF the routed path. Instance/self method
    # calls (bootstrap -> Store.save, Store.save -> self._validate) are a known
    # UNRESOLVED boundary: the analyzer soundly declines to guess the receiver's
    # class, so no edge is emitted (asserted in the golden test). Kept non-routed
    # so this unresolved call never taints the reachable region.
    return Store().save({"ok": True})


def sync(url: str):
    # fn -> dep edge: offline.sync -> urllib3  (but sync is not routed)
    http = urllib3.PoolManager()
    return http.request("GET", url).data


def run_plugin(name: str):
    # Dynamic import by name: unresolvable. No edge may be fabricated from here.
    module = importlib.import_module(name)
    handler = getattr(module, "run")
    return handler()
