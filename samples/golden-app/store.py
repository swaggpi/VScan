"""A class whose methods call each other via ``self`` and call across files.

Exercises two hard call-resolution cases:
  * Store.save -> Store._validate   (method call via ``self``)
  * Store.save -> services.persist  (cross-file call from inside a method)
"""

from __future__ import annotations

import services


class Store:
    def save(self, record):
        self._validate(record)      # self-method call
        return services.persist(record)  # cross-file call from a method

    def _validate(self, record):
        if not record:
            raise ValueError("empty record")
        return True
