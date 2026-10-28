"""Thumbnail generator CLI -- uses Pillow, not reachable from any route.

Run manually to regenerate report thumbnails. Guarded by ``__main__`` and never
imported by the web service, so the old ``Pillow`` pin is unreachable.
"""

from PIL import Image

_SIZE = (128, 128)


def make_thumbnail(source_path, dest_path):
    """Create a thumbnail of ``source_path`` at ``dest_path`` using Pillow."""
    image = Image.open(source_path)
    image.resize(_SIZE).save(dest_path)


if __name__ == "__main__":  # pragma: no cover
    import sys

    make_thumbnail(sys.argv[1], sys.argv[2])
