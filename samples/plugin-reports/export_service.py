"""Report XML export via a reflectively-selected lxml parser.

``lxml.etree`` is imported statically, but every etree call -- the parser
constructor, the parse, the serialise -- is resolved by name at request time, so
static call resolution never draws a ``calls`` edge to lxml. lxml shows as "not
reached"; the inferred-edge tier recovers the dynamic path. The parser is built
with entity resolution enabled, so attacker XML can read local files (XXE).
"""

from lxml import etree  # lxml 4.5.0 -- imported here, invoked only by name below


def export_report_xml(raw):
    """Round-trip an untrusted XML report through a reflectively-built parser."""
    parse = getattr(etree, "fromstring")
    serialise = getattr(etree, "tostring")
    parser_cls = getattr(etree, "XMLParser")
    # resolve_entities left on -> external entities in attacker XML are expanded.
    parser = parser_cls(resolve_entities=True, no_network=False)
    tree = parse(raw, parser)
    return serialise(tree)
