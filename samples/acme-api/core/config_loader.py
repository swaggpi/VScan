"""YAML configuration loader -- the flagship sink lives here.

``load_spec`` forwards its argument to ``parse_yaml`` (a same-module sibling),
which calls ``yaml.full_load``. On PyYAML 5.3.1 that function deserializes
arbitrary Python objects (via the ``python/object/new`` constructor), which is
exactly the unsafe behavior described by CVE-2020-14343. So when
attacker-controlled text reaches it (via ``POST /documents/import``) the result
is remote code execution -- the flow the taint pass proves end to end.

The import is aliased (``import yaml as _yaml``) so call resolution must follow
the alias back to the PyYAML distribution.
"""

import yaml as _yaml


def load_spec(text):
    """Load a configuration/document spec from raw YAML text.

    ``text`` is forwarded unchanged into ``parse_yaml`` so that, on the flagship
    path, attacker input stays live all the way to the sink.
    """
    return parse_yaml(text)


def parse_yaml(text):
    """Deserialize YAML text into a Python object.

    UNSAFE on PyYAML 5.3.1: ``yaml.full_load`` is the function named by
    CVE-2020-14343 as susceptible to arbitrary code execution on untrusted
    input.
    """
    return _yaml.full_load(text)
