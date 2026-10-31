"""Operator/cron jobs -- NOT wired to any HTTP route.

Everything here is invoked from the command line or a scheduler, never from a
public request handler. Dependencies reached only from this package (urllib3,
paramiko) are therefore genuinely unreachable from the running web service.
"""
