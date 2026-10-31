"""XML export CLI -- uses lxml, not reachable from any route.

Serializes stored documents to an XML report offline. Guarded by ``__main__``
and never imported by the web service, so the old ``lxml`` pin is unreachable.
"""

from lxml import etree


def export(records):
    """Serialize a list of record dicts to an XML byte string via lxml."""
    root = etree.Element("documents")
    for record in records:
        child = etree.SubElement(root, "document")
        child.text = str(record)
    return etree.tostring(root)


if __name__ == "__main__":  # pragma: no cover
    print(export([{"id": 1}]))
