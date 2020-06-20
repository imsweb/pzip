import builtins

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

__version__ = "0.9.8"
__version_info__ = tuple(int(num) for num in __version__.split("."))


def open(fileobj, mode, *, key=None, **kwargs):
    if isinstance(fileobj, str):
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
