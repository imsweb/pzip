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

__version__ = "0.9.2"
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

    class Close(enum.Enum):
        REWIND = -1
        NEVER = 0
        ALWAYS = 1
        AUTOMATIC = 2

        def close(self, fileobj):
            if self == PZip.Close.AUTOMATIC:
                # Rewind (and leave open) if the fileobj is a BytesIO, otherwise close unless it's interactive.
                if isinstance(fileobj, io.BytesIO):
                    fileobj.seek(0)
                elif not fileobj.isatty():
                    fileobj.close()
            elif self == PZip.Close.ALWAYS:
                # Always close the underlying fileobj.
                fileobj.close()
            elif self == PZip.Close.NEVER:
                # Leave the underlying fileobj open.
                pass
            elif self == PZip.Close.REWIND:
                # Rewind (and leave open) the fileobj.
                fileobj.seek(0)

    def __init__(
        self,
        fileobj,
        mode,
        secret_key=None,
        name=None,
        key_size=None,
        iterations=None,
        nonce=None,
        compress=True,
        decompress=True,
        close=Close.AUTOMATIC,
    ):
        self.mode = PZip.Mode(mode)
        if isinstance(fileobj, str):
            self.fileobj = open(fileobj, self.mode.value)
        else:
            self.fileobj = fileobj
        self.name = name or getattr(self.fileobj, "name", None)
        self.version = 1
        self.flags = PZip.Flags(0)
        self.size = 0
        self.close_mode = PZip.Close(close)
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
                except zlib.error as e:
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
            except (InvalidTag, zlib.error) as e:
                raise InvalidFile() from e
        return data

    def isatty(self):
        return False

    def close(self):
        if self.mode == PZip.Mode.ENCRYPT:
            if self.compressed:
                remaining = self.compressor.flush()
                if remaining:
                    self.fileobj.write(self.context.update(remaining))
            self.fileobj.write(self.context.finalize())
            self.update_header(self.context.tag)
        self.close_mode.close(self.fileobj)

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


def copy(infile, outfile, progress=None):
    """
    Copies infile to outfile in chunks, optionally updating a progress bar. Closes infile and outfile upon completion,
    if they are not interactive.
    """
    while True:
        chunk = infile.read(PZip.DEFAULT_CHUNK_SIZE)
        if not chunk:
            break
        outfile.write(chunk)
        if progress:
            progress.update(len(chunk))
    if progress:
        progress.close()
    if not infile.isatty() and not isinstance(infile, io.BytesIO):
        infile.close()
    if not outfile.isatty() and not isinstance(outfile, io.BytesIO):
        outfile.close()


def get_files(filename, mode, key, options):
    """
    Given an input filename (possibly None for STDIN), a mode (ENCRYPT or DECRYPT), a key, and the command line
    options, this method will return a tuple:

        (infile, outfile, total)

    Where infile and outfile will be open and ready to read/write, and total is the number of expected bytes to read
    from infile.
    """
    infile = None
    outfile = None
    total = None
    if options.stdout:
        outfile = sys.stdout.buffer
    elif options.output:
        outfile = open(options.output, "wb")
    if mode == PZip.Mode.ENCRYPT:
        if filename:
            infile = open(filename, "rb")
            # If not already specified, set output file to <filename>.pz.
            outfile = outfile or open(filename + ".pz", "wb")
            # Progress total will be the size of the input file when encrypting.
            total = os.path.getsize(filename)
        else:
            infile = sys.stdin.buffer
            # If using STDIN and no output was specified, use a default filename.
            outfile = outfile or open("output.pz", "wb")
        # Wrap the output file in a PZip object.
        outfile = PZip(outfile, mode, key, iterations=options.iterations, compress=not options.nozip)
    elif mode == PZip.Mode.DECRYPT:
        infile = PZip(filename or sys.stdin.buffer, mode, key, decompress=not options.extract)
        # PZip's read will return uncompressed data by default, so this should be the uncompressed plaintext size.
        total = infile.size
        if not outfile:
            if filename:
                # If an output wasn't specified, and we have a filename, strip off the last suffix (.pz).
                new_filename = filename.rsplit(".", 1)[0]
                if options.extract and infile.compressed:
                    # Special case for when we're just extracting the compressed data, add a .gz suffix.
                    # TODO: get this suffix from the PZip object, in case we add compression options.
                    new_filename += ".gz"
                    # Set the progress total to the filesize (minus header), since we aren't decompressing.
                    total = os.path.getsize(filename) - infile.header_size - 16
                outfile = open(new_filename, "wb")
            else:
                # Using STDIN and no output was specified, just dump to STDOUT.
                outfile = sys.stdout.buffer
    return infile, outfile, total


def main(*args):
    logging.basicConfig(format="{levelname} {message}", style="{")
    parser = argparse.ArgumentParser()
    parser.add_argument("-z", "--compress", action="store_true", default=False, help="force compression")
    parser.add_argument("-d", "--decompress", action="store_true", default=False, help="force decompression")
    parser.add_argument("-k", "--keep", action="store_true", default=False, help="keep input files")
    parser.add_argument("-c", "--stdout", action="store_true", default=False, help="write to stdout (implies -k -q)")
    parser.add_argument("-e", "--key", help="encrypt using key file")
    parser.add_argument(
        "-i", "--iterations", type=int, default=PZip.DEFAULT_ITERATIONS, help="number of PBKDF2 iterations"
    )
    parser.add_argument("-o", "--output", help="specify outfile file name")
    parser.add_argument("-n", "--nozip", action="store_true", default=False, help="encrypt only, no compression")
    parser.add_argument("-x", "--extract", action="store_true", default=False, help="extract data, no decompression")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="no output")
    parser.add_argument("files", metavar="file", nargs="*", help="files to encrypt or decrypt")
    options = parser.parse_args(args=args or None)
    if options.compress and options.decompress:
        die("cannot specify -z and -d together")
    files = []
    mode = None
    if options.compress:
        mode = PZip.Mode.ENCRYPT
    elif options.decompress:
        mode = PZip.Mode.DECRYPT
    for filename in options.files:
        if filename == "-":
            continue
        elif os.path.exists(filename):
            with open(filename, "rb") as f:
                file_mode = PZip.Mode.DECRYPT if f.read(len(PZip.MAGIC)) == PZip.MAGIC else PZip.Mode.ENCRYPT
            if mode is None:
                mode = file_mode
            elif mode != file_mode:
                die("%s: mode conflict", filename)
            files.append(filename)
        else:
            logging.warning("%s: no such file", filename)
    if mode is None:
        die("unable to determine mode; specify -z or -d")
    if not files:
        # Default to using stdin if no files were specified.
        files = [None]
    if options.stdout:
        if len(files) > 1:
            die("can only output a single file to stdout")
        options.keep = True
        options.quiet = True
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
        infile, outfile, total = get_files(filename, mode, key, options)
        progress = (
            tqdm.tqdm(desc=filename, total=total, unit="B", unit_scale=True, unit_divisor=1024)
            if filename and total and not options.quiet
            else None
        )
        copy(infile, outfile, progress=progress)
        if filename and not options.keep:
            os.remove(filename)


if __name__ == "__main__":
    main()
