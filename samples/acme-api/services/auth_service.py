"""Auth service -- standard-library only, reaches no dependency.

Tokens are signed with ``hmac``/``hashlib`` from the standard library, so no
third-party package is involved. These functions are reachable from the auth
routes but deliberately touch no vulnerable dependency.
"""

import hashlib
import hmac

_SECRET = b"demo-signing-key-not-a-real-secret"


def issue_token(username):
    """Return an HMAC-signed token for ``username`` (stdlib only)."""
    digest = hmac.new(_SECRET, username.encode("utf-8"), hashlib.sha256)
    return username + "." + digest.hexdigest()


def verify_token(token):
    """Return whether ``token`` carries a valid signature."""
    if "." not in token:
        return False
    username, signature = token.rsplit(".", 1)
    expected = hmac.new(_SECRET, username.encode("utf-8"), hashlib.sha256)
    return hmac.compare_digest(signature, expected.hexdigest())
