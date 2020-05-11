#!/usr/bin/env python

import argparse
import enum
import getpass
import io
import logging
import os
import struct
import sys
import zlib

import tqdm
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__version__ = "0.9.0"
__version_info__ = tuple(int(num) for num in __version__.split("."))


class InvalidFile(Exception):
    pass


class PZip:
    # First four bytes of any PZIP file.
    MAGIC = b"PZIP"

    # file identification (4 bytes - PZIP)
    # version (1 byte)
    # flags (2 bytes)
    # key size, in bytes (1 byte)
    # plaintext size (8 bytes)
    # iterations (4 bytes)
    # salt (16 bytes)
    # nonce (16 bytes)
    # tag (16 bytes)
    HEADER_FORMAT = "!{}sBHBQL16s16s16s".format(len(MAGIC))

    # 256-bit AES keys by default.
    DEFAULT_KEY_SIZE = 32

    # Number of PBKDF2 iterations to use by default. May increase over time.
    DEFAULT_ITERATIONS = 200000

    # Used by default for .chunks() and __iter__ methods.
    DEFAULT_CHUNK_SIZE = 64 * 2 ** 10

    class Mode(enum.Enum):
        ENCRYPT = "wb"
        DECRYPT = "rb"

    class Flags(enum.IntFlag):
        COMPRESSED = 1

    def __init__(
        self,
        fileobj,
        mode,
        secret_key=None,
        key_size=None,
        iterations=None,
        nonce=None,
        compress=True,
        decompress=True,
    ):
        self.mode = PZip.Mode(mode)
        if isinstance(fileobj, str):
            self.fileobj = open(fileobj, self.mode.value)
        else:
            self.fileobj = fileobj
        self.version = 1
        self.flags = PZip.Flags(0)
        self.size = 0
        if secret_key is None:
            # Allow a default_key implementation for using things like Django's SECRET_KEY setting.
            secret_key = self.default_key()
        if key_size is None:
            key_size = self.DEFAULT_KEY_SIZE
        # AES accepts 128-, 192-, and 256-bit keys.
        assert key_size in (16, 24, 32)
        if iterations is None:
            iterations = self.DEFAULT_ITERATIONS
        if self.mode == PZip.Mode.ENCRYPT:
            assert self.fileobj.writable() and self.fileobj.seekable()
            salt = os.urandom(16)
            nonce = nonce or os.urandom(16)
            assert isinstance(nonce, bytes) and len(nonce) == 16
            key = self.derive_key(secret_key, salt, iterations, key_size)
            if compress:
                self.flags |= PZip.Flags.COMPRESSED
                self.compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, zlib.MAX_WBITS | 16)
            self.context = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
            self.write_header(key_size, salt, iterations, nonce)
        elif self.mode == PZip.Mode.DECRYPT:
            assert self.fileobj.readable()
            self.read_header(secret_key)
            self.decompress = decompress
            if self.compressed:
                self.decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __iter__(self):
        yield from self.chunks()

    @property
    def header_size(self):
        return struct.calcsize(self.HEADER_FORMAT)

    @property
    def compressed(self):
        return self.flags & PZip.Flags.COMPRESSED

    def default_key(self):
        raise NotImplementedError("{} does not provide a default secret key.".format(self.__class__.__name__))

    def derive_key(self, secret_key, salt, iterations, key_size):
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=key_size, salt=salt, iterations=iterations, backend=default_backend()
        ).derive(secret_key)

    def write_header(self, key_size, salt, iterations, nonce):
        self.fileobj.write(
            struct.pack(
                self.HEADER_FORMAT,
                self.MAGIC,
                self.version,
                self.flags,
                key_size,
                0,
                iterations,
                salt,
                nonce,
                b"\x00" * 16,
            )
        )
        # The first 16 encrypted bytes of the file should be the nonce repeated, to allow for fast-failing on bad keys.
        self.fileobj.write(self.context.update(nonce))

    def read_header(self, secret_key):
        data = self.fileobj.read(self.header_size)
        if len(data) < self.header_size:
            raise InvalidFile("Invalid header.")
        magic, version, flags, key_size, self.size, iterations, salt, nonce, tag = struct.unpack(
            self.HEADER_FORMAT, data
        )
        assert magic == self.MAGIC
        assert version == self.version
        self.flags = PZip.Flags(flags)
        key = self.derive_key(secret_key, salt, iterations, key_size)
        self.context = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        # Once we have a decryption context, read the first 16 encrypted bytes and verify they match the nonce.
        nonce_check = self.context.update(self.fileobj.read(16))
        if nonce != nonce_check:
            raise InvalidFile()

    def update_header(self, tag):
        assert len(tag) == 16
        self.fileobj.seek(len(self.MAGIC) + 4)
        self.fileobj.write(struct.pack("!Q", self.size))
        self.fileobj.seek(self.header_size - 16)
        self.fileobj.write(tag)

    def seekable(self):
        return False

    def writable(self):
        return self.mode == PZip.Mode.ENCRYPT

    def write(self, data):
        if self.mode != PZip.Mode.ENCRYPT:
            raise io.UnsupportedOperation()
        self.size += len(data)
        if self.compressed:
            data = self.compressor.compress(data)
        if data:
            self.fileobj.write(self.context.update(data))
        return len(data)

    def readable(self):
        return self.mode == PZip.Mode.DECRYPT

    def read(self, size=-1):
        if self.mode != PZip.Mode.DECRYPT:
            raise io.UnsupportedOperation()
        data = self.fileobj.read(size)
        if data:
            data = self.context.update(data)
            if self.decompress and self.compressed:
                try:
                    data = self.decompressor.decompress(data)
                    # XXX: deal with this, ideally with a test
                    assert not self.decompressor.unconsumed_tail
                except (zlib.error, OSError) as e:
                    raise InvalidFile() from e
            done = size is None or size < 0
        else:
            done = True
        if done:
            try:
                remaining = self.context.finalize()
                if self.decompress and self.compressed and not self.decompressor.eof:
                    remaining = self.decompressor.decompress(remaining)
                    if hasattr(self.decompressor, "flush"):
                        remaining += self.decompressor.flush()
                data += remaining
            except (InvalidTag, zlib.error, OSError) as e:
                raise InvalidFile() from e
        return data

    def close(self):
        if self.mode == PZip.Mode.ENCRYPT:
            if self.compressed:
                remaining = self.compressor.flush()
                if remaining:
                    self.fileobj.write(self.context.update(remaining))
            self.fileobj.write(self.context.finalize())
            self.update_header(self.context.tag)
        if isinstance(self.fileobj, io.BytesIO):
            self.fileobj.seek(0)
        else:
            self.fileobj.close()

    # These are taken from Django, so this can be used in places where it expects a File object. They are also
    # generally useful to be able to stream a file with a specified chunk size.

    def multiple_chunks(self, chunk_size=None):
        return self.size > (chunk_size or self.DEFAULT_CHUNK_SIZE)

    def chunks(self, chunk_size=None):
        chunk_size = chunk_size or self.DEFAULT_CHUNK_SIZE
        # TODO: need a reset method to re-create context and reset file position
        while True:
            data = self.read(chunk_size)
            if not data:
                break
            yield data


def die(msg, *args, code=1):
    logging.critical(msg, *args)
    sys.exit(code)


def copy(infile, outfile, name=None, total=None):
    t = tqdm.tqdm(desc=name, total=total, unit="B", unit_scale=True, unit_divisor=1024)
    while True:
        chunk = infile.read(PZip.DEFAULT_CHUNK_SIZE)
        if not chunk:
            break
        outfile.write(chunk)
        t.update(len(chunk))
    t.close()


def main():
    logging.basicConfig(format="{levelname} {message}", style="{")
    parser = argparse.ArgumentParser()
    parser.add_argument("-z", "--compress", action="store_true", default=False, help="force compression")
    parser.add_argument("-d", "--decompress", action="store_true", default=False, help="force decompression")
    parser.add_argument("-k", "--keep", action="store_true", default=False, help="keep input files")
    parser.add_argument("-c", "--stdout", action="store_true", default=False, help="write to stdout (implies -k)")
    parser.add_argument("-e", "--key", help="encrypt using key file")
    parser.add_argument("-n", "--nozip", action="store_true", default=False, help="encrypt only, no compression")
    parser.add_argument("-x", "--extract", action="store_true", default=False, help="extract data, no decompression")
    parser.add_argument("files", metavar="file", nargs="*", help="files to encrypt or decrypt")
    options = parser.parse_args()
    if options.compress and options.decompress:
        die("cannot specify -z and -d together")
    files = []
    mode = None
    if options.compress:
        mode = PZip.Mode.ENCRYPT
    elif options.decompress:
        mode = PZip.Mode.DECRYPT
    for filename in options.files:
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                file_mode = PZip.Mode.DECRYPT if f.read(len(PZip.MAGIC)) == PZip.MAGIC else PZip.Mode.ENCRYPT
            if mode is None:
                mode = file_mode
            elif mode != file_mode:
                die("%s: mode conflict", filename)
            files.append(filename)
        else:
            logging.warning("%s: no such file", filename)
    if options.key:
        with open(options.key, "rb") as f:
            key = f.read()
    else:
        key = getpass.getpass("Key: ")
        if mode == PZip.Mode.ENCRYPT:
            verify = getpass.getpass("Verify: ")
            if verify != key:
                die("keys did not match")
        key = key.encode("utf-8")
    for filename in files:
        if mode == PZip.Mode.ENCRYPT:
            new_filename = filename + ".pz"
            with open(filename, "rb") as infile:
                with PZip(new_filename, mode, key, compress=not options.nozip) as outfile:
                    copy(infile, outfile, name=filename, total=os.path.getsize(filename))
        elif mode == PZip.Mode.DECRYPT:
            new_filename = filename.rsplit(".", 1)[0]
            if new_filename == filename:
                # TODO: die here?
                pass
            with PZip(filename, mode, key, decompress=not options.extract) as infile:
                if options.extract and infile.compressed:
                    new_filename += ".gz"
                with open(new_filename, "wb") as outfile:
                    total = os.path.getsize(filename) - infile.header_size - 16 if options.extract else infile.size
                    copy(infile, outfile, name=filename, total=total)
        if not options.keep:
            os.remove(filename)


if __name__ == "__main__":
    main()
