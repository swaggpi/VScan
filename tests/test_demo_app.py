"""Reachability assertions for the ``samples/demo-app`` demo fixture.

These are offline and deterministic: they run the structural scan and the pure
reachability computation, and assert the shape of the result. They deliberately
make NO assertions about CVE data (that requires a live OSV query and changes
over time) -- only about which public entry point reaches which dependency and
how deep the resolved chain is.

The fixture is designed to showcase the engine, so the assertions pin exactly
that showcase:

* two outdated dependencies (PyYAML, Jinja2) are each reachable from a public
  route through a deep (>= 4 function-hop) call chain that resolves end to end;
* one current dependency (requests) is reachable (the reachable-but-safe case);
* the two "decoy" outdated dependencies (urllib3, Pillow) are NOT reachable from
  any public entry point, and -- because the reachable region is fully resolved
  -- are classified ``unreachable`` rather than ``potentially_reachable``.
"""

from __future__ import annotations

import os

from scanner.reachability import (
    REACHABLE,
    UNREACHABLE,
    EntrypointReachability,
    ReachabilityResult,
    compute_reachability,
)
from scanner.scan import scan_repo

_DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples",
    "demo-app",
)


def _reach() -> ReachabilityResult:
    return compute_reachability(scan_repo(_DEMO))


def _entrypoint(result: ReachabilityResult, ep_id: str) -> EntrypointReachability:
    for ep in result.entrypoints:
        if ep.id == ep_id:
            return ep
    raise AssertionError(f"entrypoint {ep_id} not found in result")


def _function_hops(example_path: list[str]) -> int:
    """Number of ``fn:`` nodes on an example path (its function-hop depth)."""
    return sum(1 for node in example_path if node.startswith("fn:"))


# -- reachable deep chains --------------------------------------------------


def test_configs_import_reaches_pyyaml_through_deep_chain():
    result = _reach()
    ep = _entrypoint(result, "ep:POST:/configs/import")

    reached = {d.id for d in ep.reachable_dependencies}
    assert "dep:PyPI:PyYAML" in reached

    pyyaml = next(d for d in ep.reachable_dependencies if d.id == "dep:PyPI:PyYAML")
    assert "load" in (pyyaml.symbol or "")
    # The chain controller -> service -> validation -> parser -> loader -> dep
    # must resolve end to end, at least four function hops deep.
    assert _function_hops(pyyaml.example_path) >= 4
    assert pyyaml.example_path[0] == "ep:POST:/configs/import"
    assert pyyaml.example_path[-1] == "dep:PyPI:PyYAML"
    assert pyyaml.verdict == REACHABLE
    # Nothing on this route's reachable region was left unresolved.
    assert ep.unresolved_calls_encountered == 0


def test_reports_route_reaches_jinja2_through_deep_chain():
    result = _reach()
    ep = _entrypoint(result, "ep:GET:/reports/<report_id>")

    reached = {d.id for d in ep.reachable_dependencies}
    assert "dep:PyPI:Jinja2" in reached

    jinja = next(d for d in ep.reachable_dependencies if d.id == "dep:PyPI:Jinja2")
    assert "escape" in (jinja.symbol or "")
    assert _function_hops(jinja.example_path) >= 4
    assert jinja.example_path[0] == "ep:GET:/reports/<report_id>"
    assert jinja.example_path[-1] == "dep:PyPI:Jinja2"
    assert jinja.verdict == REACHABLE
    assert ep.unresolved_calls_encountered == 0


def test_health_reaches_requests_the_safe_dependency():
    result = _reach()
    ep = _entrypoint(result, "ep:GET:/health")
    reached = {d.id for d in ep.reachable_dependencies}
    # ``requests`` is current/patched but genuinely reachable: the engine should
    # still report it as reached (the finding layer is what suppresses it).
    assert "dep:PyPI:requests" in reached


# -- unreachable decoys -----------------------------------------------------


def test_outdated_decoys_are_not_reachable():
    result = _reach()
    reachable_ids = {d["id"] for d in result.repo.reachable_deps}

    # urllib3 (maintenance job) and Pillow (CLI tool) are declared and called,
    # but by no public route -- they must not appear in the reachable set.
    assert "dep:PyPI:urllib3" not in reachable_ids
    assert "dep:PyPI:Pillow" not in reachable_ids

    # And they must never leak into any single entry point's reachable set.
    for ep in result.entrypoints:
        ep_reached = {d.id for d in ep.reachable_dependencies}
        assert "dep:PyPI:urllib3" not in ep_reached
        assert "dep:PyPI:Pillow" not in ep_reached


def test_decoys_are_confidently_unreachable_not_merely_potential():
    result = _reach()
    # The whole reachable region resolves cleanly (every public route is wired
    # to a handler and carries zero unresolved calls), so the decoys earn the
    # confident ``unreachable`` verdict rather than ``potentially_reachable``.
    assert result.repo.reachable_region_fully_resolved is True
    assert result.repo.verdict_by_dep["dep:PyPI:urllib3"] == UNREACHABLE
    assert result.repo.verdict_by_dep["dep:PyPI:Pillow"] == UNREACHABLE
    # The reachable outdated deps carry the reachable verdict.
    assert result.repo.verdict_by_dep["dep:PyPI:PyYAML"] == REACHABLE
    assert result.repo.verdict_by_dep["dep:PyPI:Jinja2"] == REACHABLE
