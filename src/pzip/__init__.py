import builtins
import importlib.metadata

from .base import (
    Algorithm,
    Close,
    Compression,
    InvalidFile,
    Key,
    KeyDerivation,
    KeyMaterial,
    Password,
    PZip,
    RawKey,
    Tag,
)
from .reader import PZipReader
from .writer import PZipWriter

__version__ = importlib.metadata.version("pzip")
__version_info__ = tuple(
    int(num) if num.isdigit() else num for num in __version__.split(".")
)


def open(fileobj, mode="rb", *, key=None, **kwargs):
    if isinstance(fileobj, (str, int)):
        fileobj = builtins.open(fileobj, mode)
    if "r" in mode:
        return PZipReader(fileobj, key, **kwargs)
    elif "w" in mode:
        return PZipWriter(fileobj, key, **kwargs)
    raise ValueError("Invalid mode: {}".format(mode))


__all__ = [
    "Algorithm",
    "Close",
    "Compression",
    "InvalidFile",
    "Key",
    "KeyDerivation",
    "KeyMaterial",
    "Password",
    "PZip",
    "RawKey",
    "Tag",
    "open",
]
