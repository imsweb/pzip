#!/usr/bin/env python

import enum
import gzip
import io
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import deflate

    gzip_compress = deflate.gzip_compress
    gzip_decompress = deflate.gzip_decompress
except ImportError:
    gzip_compress = gzip.compress
    gzip_decompress = gzip.decompress


__all__ = [
    "InvalidFile",
    "PZip",
    "Algorithm",
    "Tag",
    "KeyDerivation",
    "Compression",
    "Close",
    "KeyMaterial",
    "RawKey",
    "Key",
    "Password",
]


class InvalidFile(Exception):
    pass


# Number of PBKDF2 iterations to use by default. May increase over time.
DEFAULT_ITERATIONS = 200000


class Flag(enum.IntFlag):
    APPEND_LENGTH = 1 << 0


class BlockFlag(enum.IntFlag):
    LAST = 1 << 7


@enum.unique
class Algorithm(enum.IntEnum):
    AES_GCM_256 = 1

    def initialize(self, key, tags):
        return AESGCM(key)

    def key_length(self):
        return 32

    def tag_length(self):
        return 16

    def get_tags(self, **kwargs):
        return {
            Tag.NONCE: kwargs.get("nonce") or os.urandom(12),
        }


@enum.unique
class Tag(enum.IntEnum):
    NONCE = 1
    KDF_SALT = 2
    KDF_ITERATIONS = -3
    KDF_INFO = 4
    FILENAME = 5
    APPLICATION = 6
    MIMETYPE = 7
    COMMENT = 127


@enum.unique
class KeyDerivation(enum.IntEnum):
    NONE = 0
    HKDF_SHA256 = 1
    PBKDF2_SHA256 = 2

    def get_tags(self, **kwargs):
        if self.value == 1:
            return {
                Tag.KDF_SALT: kwargs.get("salt") or os.urandom(32),
                Tag.KDF_INFO: kwargs.get("info"),
            }
        elif self.value == 2:
            return {
                Tag.KDF_SALT: kwargs.get("salt") or os.urandom(32),
                Tag.KDF_ITERATIONS: kwargs.get("iterations") or DEFAULT_ITERATIONS,
            }
        return {}

    def derive(self, key, algorithm, tags):
        if isinstance(key, (memoryview, bytearray)):
            key = bytes(key)
        if not self.value:
            assert isinstance(key, bytes)
            assert len(key, algorithm.key_length())
            return key
        elif self.value == 1:
            assert isinstance(key, bytes)
            return HKDF(
                algorithm=hashes.SHA256(),
                length=algorithm.key_length(),
                salt=tags[Tag.KDF_SALT],
                info=tags.get(Tag.KDF_INFO),
                backend=default_backend(),
            ).derive(key)
        elif self.value == 2:
            if isinstance(key, str):
                key = key.encode("utf-8")
            assert isinstance(key, bytes)
            return PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=algorithm.key_length(),
                salt=tags[Tag.KDF_SALT],
                iterations=tags[Tag.KDF_ITERATIONS],
                backend=default_backend(),
            ).derive(key)
        raise Exception("Unknown key derivation function.")


@enum.unique
class Compression(enum.IntEnum):
    NONE = 0
    GZIP = 1

    @classmethod
    def resolve(cls, arg):
        if (arg is True) or (arg is None):
            return Compression.GZIP, 6
        elif arg is False:
            return Compression.NONE, None
        elif isinstance(arg, Compression):
            return arg, None
        elif isinstance(arg, int):
            return Compression.GZIP, arg
        elif isinstance(arg, (list, tuple)):
            assert len(arg) == 2
            assert isinstance(arg[0], Compression)
            assert arg[1] is None or isinstance(arg[1], int)
            return arg
        raise TypeError("Unknown compression type.")

    def __call__(self, level=None):
        # Allows for Compression.GZIP(level)
        return (self, level)

    def compress(self, data, level=None):
        if self == Compression.NONE:
            return data
        elif self == Compression.GZIP:
            return gzip_compress(data, level)

    def decompress(self, data):
        if self == Compression.NONE:
            return data
        elif self == Compression.GZIP:
            return gzip_decompress(data)


class Close(enum.Enum):
    REWIND = -1
    NEVER = 0
    ALWAYS = 1
    AUTOMATIC = 2

    def close(self, fileobj):
        if self == Close.AUTOMATIC:
            # Rewind (and leave open) if the fileobj is a BytesIO, otherwise close unless it's interactive.
            if isinstance(fileobj, io.BytesIO):
                fileobj.seek(0)
            elif not fileobj.isatty():
                fileobj.close()
        elif self == Close.ALWAYS:
            # Always close the underlying fileobj.
            fileobj.close()
        elif self == Close.NEVER:
            # Leave the underlying fileobj open.
            pass
        elif self == Close.REWIND:
            # Rewind (and leave open) the fileobj.
            fileobj.seek(0)


class KeyMaterial:
    kdf = KeyDerivation.NONE

    def __init__(self, material, kdf=None, **kwargs):
        self.material = material
        self.kdf = kdf or self.__class__.kdf
        self.kdf_kwargs = kwargs

    @classmethod
    def resolve(cls, arg):
        if isinstance(arg, KeyMaterial):
            return arg
        elif isinstance(arg, str):
            return Password(arg)
        elif isinstance(arg, (bytes, bytearray, memoryview)):
            return Key(arg)
        raise TypeError("Unknown key material type ({}).".format(arg.__class__.__name__))

    def get_tags(self):
        return self.kdf.get_tags(**self.kdf_kwargs)


class RawKey(KeyMaterial):
    pass


class Key(KeyMaterial):
    kdf = KeyDerivation.HKDF_SHA256


class Password(KeyMaterial):
    kdf = KeyDerivation.PBKDF2_SHA256


class PZip(io.RawIOBase):
    # First two bytes of any PZIP file.
    MAGIC = b"\xB6\x9E"  # ¶ž

    # PZip header format (for struct):
    # magic, version, flags, algorithm, kdf, compression, #tags
    HEADER_FORMAT = "!2s6B"

    # PZip header size.
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    # Default plaintext block size when encrypting.
    # Benchmarking suggests that block sizes in the 256k-1MB range perform best.
    DEFAULT_BLOCK_SIZE = 2 ** 18  # 256k

    def __init__(
        self, fileobj, name=None, close=Close.AUTOMATIC,
    ):
        self.version = 1
        self.flags = Flag(0)
        self.algorithm = Algorithm.AES_GCM_256
        self.kdf = KeyDerivation.NONE
        self.compression = Compression.NONE
        self.tags = {}
        self.fileobj = fileobj
        self.name = name or getattr(self.fileobj, "name", None)
        self.close_mode = Close(close)
        self.counter = 0
        self.buffer = bytearray()

    @property
    def append_length(self):
        return Flag.APPEND_LENGTH in self.flags

    def initialize(self, key):
        material = key.material if isinstance(key, KeyMaterial) else key
        key = self.kdf.derive(material, self.algorithm, self.tags)
        self.cipher = self.algorithm.initialize(key, self.tags)

    def next_nonce(self):
        """
        Computes the next block nonce, based on the original nonce and current counter, then increments the counter.
        The nonce for block number B with original nonce N is essentially N^B, where B is a 32-bit unsigned big-endian
        integer, left-padded to the length of N with zero bytes.
        """
        nonce = bytearray(self.tags[Tag.NONCE])
        ctr = struct.pack("!L", self.counter)
        i = len(nonce) - len(ctr)
        for c in range(len(ctr)):
            nonce[i + c] ^= ctr[c]
        self.counter += 1
        return bytes(nonce)

    def close(self):
        if not self.closed:
            self.close_mode.close(self.fileobj)
        super().close()
