"""Health router -- operational status and version.

A single read-only route used by load balancers and uptime checks. It reaches
only the config layer (standard-library env reads), so it adds breadth without
touching any third-party sink.
"""

from fastapi import APIRouter

from core import config

router = APIRouter(tags=["ops"])


@router.get("/health")
def health():
    """Public route: liveness + effective runtime settings summary."""
    return {"status": "ok", "settings": config.describe()}
