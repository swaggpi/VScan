"""Report-spec import via a reflectively-selected YAML loader (PyYAML).

``yaml`` is imported statically, but the loader function is looked up by name at
request time, so the ``yaml.unsafe_load`` call is never resolved to a ``calls``
edge. PyYAML therefore shows as "not reached"; the inferred-edge tier recovers
the dynamic path. ``unsafe_load`` on attacker bytes is unsafe deserialisation.
"""

import yaml  # PyYAML 5.3.1 -- imported here, invoked only by name below


def load_report_spec(raw):
    """Deserialise an untrusted report spec with a reflectively-chosen loader."""
    yaml_load = _resolve_loader()
    return yaml_load(raw)


def _resolve_loader():
    # The loader is looked up by name, so the yaml.unsafe_load call is invisible
    # to static resolution -- and unsafe_load constructs arbitrary Python objects.
    return getattr(yaml, "unsafe_load")
