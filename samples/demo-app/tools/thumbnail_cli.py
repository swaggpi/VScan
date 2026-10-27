"""Thumbnail generator -- a developer CLI, not part of the web service.

Run manually to regenerate report thumbnails:

    python -m tools.thumbnail_cli input.png output.png

It uses ``Pillow`` (an outdated pin with known advisories), but it is a
command-line script guarded by ``__main__`` and is never imported or called by
any HTTP route, so it is unreachable from the running service.
"""

from PIL import Image

_THUMBNAIL_SIZE = (128, 128)


def make_thumbnail(source_path, dest_path):
    """Create a thumbnail of ``source_path`` at ``dest_path`` using Pillow."""
    image = Image.open(source_path)
    thumbnail = image.resize(_THUMBNAIL_SIZE)
    thumbnail.save(dest_path)


if __name__ == "__main__":  # pragma: no cover
    import sys

    make_thumbnail(sys.argv[1], sys.argv[2])
