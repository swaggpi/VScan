"""Artifact-signing CLI -- uses cryptography, not reachable from any route.

Generates a signing key for release artifacts offline. Guarded by ``__main__``
and never imported by the web service, so the old ``cryptography`` pin is
unreachable from the running service.
"""

from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key():
    """Generate an RSA private key for signing release artifacts."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


if __name__ == "__main__":  # pragma: no cover
    generate_key()
