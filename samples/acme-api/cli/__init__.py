"""Developer command-line tools -- NOT part of the web service.

Each module here is a standalone script guarded by ``__main__`` and is never
imported by a route handler. Dependencies reached only from this package
(Pillow, lxml, cryptography) are unreachable from the running service.
"""
