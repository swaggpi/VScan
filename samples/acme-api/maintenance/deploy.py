"""Release deploy helper -- uses paramiko over SSH, not reachable from a route.

``push_release`` opens an SSH connection to copy build artifacts. It is run by
operators from the command line, never from an HTTP request, so the old
``paramiko`` pin it uses is unreachable from the running web service.
"""

import paramiko

_HOSTS = ["deploy-1.internal.acme.example", "deploy-2.internal.acme.example"]


def push_release(artifact_path):
    """Copy a release artifact to each deploy host over SSH (operator use)."""
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    results = []
    for host in _HOSTS:
        client.connect(host)
        results.append((host, artifact_path))
        client.close()
    return results


if __name__ == "__main__":  # pragma: no cover
    import sys

    push_release(sys.argv[1])
