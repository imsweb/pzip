#!/usr/bin/env python

import argparse
import enum
import getpass
import gzip
import io
import os
import secrets
import struct
import sys
import zlib

import tqdm
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__version__ = "0.9.8"
__version_info__ = tuple(int(num) for num in __version__.split("."))
__all__ = ["InvalidFile", "PZip"]


class InvalidFile(Exception):
    pass


def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


def _compress(data, compresslevel=9, mtime=0):
    """
    Basically a copy of gzip.compress, but with mtime=0 for Python before 3.8, when it was added as a param.
    """
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=compresslevel, mtime=mtime) as f:
        f.write(data)
    return buf.getvalue()


class PZip:
    # First four bytes of any PZIP file.
    MAGIC = b"PZIP"

    # file identification (4 bytes - PZIP)
    # version (1 byte)
    # flags (1 byte)
    # key size, in bytes (1 byte)
    # nonce size, in bytes (1 bytes)
    # kdf salt (16 bytes)
    # kdf iterations (4 bytes)
    # plaintext size (8 bytes)
    HEADER_FORMAT = "!{}sBBBB16sLQ".format(len(MAGIC))
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    # 256-bit AES keys by default.
    DEFAULT_KEY_SIZE = 32

    # 96-bit IV/nonce by default.
    DEFAULT_NONCE_SIZE = 12

    # Number of PBKDF2 iterations to use by default. May increase over time.
    DEFAULT_ITERATIONS = 200000

    # Default (approximate) plaintext block size when encrypting. Actaul blocks may be larger or smaller than this.
    # Benchmarking suggests that block sizes in the 256k-1MB range perform best.
    DEFAULT_BLOCK_SIZE = 2 ** 18  # 256k

    class Mode(enum.Enum):
        ENCRYPT = "wb"
        DECRYPT = "rb"

    class Flags(enum.IntFlag):
        COMPRESSED = 1 << 0
        PASSWORD = 1 << 1

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
        mode="rb",
        secret_key=None,
        password=None,
        name=None,
        size=None,
        key_size=None,
        nonce=None,
        salt=None,
        iterations=None,
        block_size=None,
        compress=True,
        decompress=True,
        peek=False,
        close=Close.AUTOMATIC,
    ):
        self.version = 1
        self.mode = PZip.Mode(mode)
        if secret_key and password:
            raise ValueError("Specify a secret_key or a password, not both.")
        if isinstance(fileobj, str):
            self.fileobj = open(fileobj, self.mode.value)
        else:
            self.fileobj = fileobj
        self.name = name or getattr(self.fileobj, "name", None)
        # For streaming usage, or non-seekable outputs, plaintext size can be passed explicitly.
        # If this is None, it will be updated after each write, and PZip will try to update the header on close.
        self.size = size
        self.flags = PZip.Flags(0)
        self.close_mode = PZip.Close(close)
        self.closed = False
        if secret_key:
            # If a secret_key (presumably random bits) was specified, use HKDF for speed.
            key_material = secret_key
        elif password:
            # If a password was specified, use PBKDF2 to slow down attacks.
            key_material = password
            self.flags |= PZip.Flags.PASSWORD
        else:
            try:
                # Allow a default_key implementation for using things like Django's SECRET_KEY setting.
                key_material = self.default_key()
            except NotImplementedError:
                if self.mode == PZip.Mode.ENCRYPT:
                    raise ValueError("You must provide a secret_key or password when encrypting.")
                # Let this be None when reading files, in case we just want to read the header.
                key_material = None
        self.counter = 0
        self.buffer = b""
        if self.mode == PZip.Mode.ENCRYPT:
            assert self.fileobj.writable()
            self.key_size = key_size or self.DEFAULT_KEY_SIZE
            # AES accepts 128-, 192-, and 256-bit keys.
            if self.key_size not in (16, 24, 32):
                raise ValueError("key_size must be 16, 24, or 32.")
            self.nonce = nonce or os.urandom(self.DEFAULT_NONCE_SIZE)
            self.nonce_size = len(self.nonce)
            self.salt = salt or os.urandom(16)
            self.iterations = iterations or self.DEFAULT_ITERATIONS
            self.key = self.derive_key(key_material)
            if compress:
                self.flags |= PZip.Flags.COMPRESSED
                self.compresslevel = zlib.Z_DEFAULT_COMPRESSION if compress is True else int(compress)
            self.block_size = block_size or self.DEFAULT_BLOCK_SIZE
            self.write_header()
            self.bytes_written = 0
        elif self.mode == PZip.Mode.DECRYPT:
            assert self.fileobj.readable()
            self.decompress = decompress
            self.read_header(key_material)
            if peek:
                self.buffer = self.read_block()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __iter__(self):
        yield from self.chunks()

    def __del__(self):
        try:
            self.close()
        except:  # noqa
            # Not much we can do at this point.
            pass

    @property
    def compressed(self):
        return self.flags & PZip.Flags.COMPRESSED

    @property
    def password(self):
        return self.flags & PZip.Flags.PASSWORD

    def default_key(self):
        raise NotImplementedError("{} does not provide a default secret key.".format(self.__class__.__name__))

    def derive_key(self, key_material):
        if self.password:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_size,
                salt=self.salt,
                iterations=self.iterations,
                backend=default_backend(),
            )
        else:
            kdf = HKDF(
                algorithm=hashes.SHA256(), length=self.key_size, salt=self.salt, info=None, backend=default_backend()
            )
        return kdf.derive(key_material)

    def write_header(self):
        """
        Writes the PZip header and nonce.
        """
        self.fileobj.write(
            struct.pack(
                self.HEADER_FORMAT,
                self.MAGIC,
                self.version,
                self.flags,
                self.key_size,
                self.nonce_size,
                self.salt,
                self.iterations if self.password else 0,
                self.size or 0,
            )
        )
        self.fileobj.write(self.nonce)

    def read_header(self, key_material):
        """
        Reads the PZip header and nonce, and generates the key based on header data and key_material.
        """
        data = self.fileobj.read(self.HEADER_SIZE)
        if len(data) < self.HEADER_SIZE:
            raise InvalidFile("Invalid PZip header.")
        (
            magic,
            self.version,
            flags,
            self.key_size,
            self.nonce_size,
            self.salt,
            self.iterations,
            self.size,
        ) = struct.unpack(self.HEADER_FORMAT, data)
        if magic != self.MAGIC:
            raise InvalidFile("File is not a PZip archive.")
        if self.version != 1:
            raise InvalidFile("Invalid or unknown file version ({}).".format(self.version))
        if self.key_size not in (16, 24, 32):
            raise InvalidFile("Invalid key_size ({}): must be 16, 24, or 32.".format(self.key_size))
        self.flags = PZip.Flags(flags)
        self.key = self.derive_key(key_material) if key_material else None
        self.nonce = self.fileobj.read(self.nonce_size)
        if len(self.nonce) != self.nonce_size:
            raise InvalidFile("Error reading nonce.")

    def _ciphertext_size(self):
        """
        Calculates the total ciphertext size, minus block headers and authentication tags. Will raise an exception if
        the underlying file object is not seekable.
        """
        assert self.readable()
        # Remember where we were, so we can reset the file position when we're done.
        old_pos = self.fileobj.tell()
        # Start reading after the header/nonce, at the first block header.
        self.fileobj.seek(PZip.HEADER_SIZE + len(self.nonce))
        total = 0
        while True:
            data = self.fileobj.read(4)
            if not data:
                # No more blocks, reset the file position and return the total size thus far.
                self.fileobj.seek(old_pos)
                return total
            block_size = struct.unpack("!L", data)[0]
            # Subtract out the GCM authentication tag length from each block.
            total += block_size - 16
            # Seek forward block_size bytes.
            self.fileobj.seek(block_size, 1)

    def next_nonce(self):
        """
        Computes the next block nonce, based on the original nonce and current counter, then increments the counter.
        The nonce for block number B with original nonce N is essentially N^B, where B is a 32-bit unsigned big-endian
        integer, left-padded to the length of N with zero bytes.
        """
        counter_bytes = (b"\x00" * (len(self.nonce) - 4)) + struct.pack("!L", self.counter)
        self.counter += 1
        return xor_bytes(self.nonce, counter_bytes)

    def seekable(self):
        return False

    def writable(self):
        return self.mode == PZip.Mode.ENCRYPT

    def write_block(self, plaintext):
        """
        Writes a block of plaintext including the block header (size), after compressing and encrypting it.
        """
        assert self.writable()
        self.bytes_written += len(plaintext)
        if self.compressed:
            plaintext = _compress(plaintext, self.compresslevel)
        ciphertext = AESGCM(self.key).encrypt(self.next_nonce(), plaintext, None)
        self.fileobj.write(struct.pack("!L", len(ciphertext)))
        self.fileobj.write(ciphertext)

    def write(self, data):
        """
        Buffers an arbitrary amount of data to be written using write_block. Blocks will not be written until the
        buffer is at least block_size bytes, or the file is closed.
        """
        if self.mode != PZip.Mode.ENCRYPT:
            raise io.UnsupportedOperation()
        self.buffer += data
        if len(self.buffer) >= self.block_size:
            self.write_block(self.buffer)
            self.buffer = b""
        return len(data)

    def flush(self):
        if self.buffer and self.mode == PZip.Mode.ENCRYPT:
            self.write_block(self.buffer)
            self.buffer = b""

    def readable(self):
        return self.mode == PZip.Mode.DECRYPT

    def read_block(self):
        """
        Reads a full block of ciphertext, including the block header (size), and decrypts/decompresses it to return
        a block of plaintext. Raises InvalidFile if the block could not be authenticated.
        """
        assert self.readable()
        block_header = self.fileobj.read(4)
        if not block_header:
            return b""
        if len(block_header) != 4:
            raise InvalidFile("Error reading header for block {}.".format(self.counter))
        block_size = struct.unpack("!L", block_header)[0]
        ciphertext = self.fileobj.read(block_size)
        try:
            plaintext = AESGCM(self.key).decrypt(self.next_nonce(), ciphertext, None)
        except InvalidTag as e:
            raise InvalidFile() from e
        if self.compressed and self.decompress:
            plaintext = gzip.decompress(plaintext)
        return plaintext

    def read(self, size=-1):
        """
        Reads an arbitrary amount of data, buffering any unread bytes of the last read block.
        """
        if self.mode != PZip.Mode.DECRYPT:
            raise io.UnsupportedOperation()
        read_all = size is None or size < 0
        while read_all or (len(self.buffer) < size):
            block = self.read_block()
            if not block:
                break
            self.buffer += block
        try:
            return self.buffer if read_all else self.buffer[:size]
        finally:
            # Trim how much we returned off the front of the buffer.
            self.buffer = b"" if read_all else self.buffer[size:]

    def isatty(self):
        return False

    def close(self):
        if self.closed:
            return
        if self.mode == PZip.Mode.ENCRYPT:
            self.flush()
            if self.size is None and self.fileobj.seekable():
                # If size was not set explicitly, and the file is seekable, update the header with the bytes written.
                pos = self.fileobj.tell()
                self.fileobj.seek(PZip.HEADER_SIZE - 8)
                self.fileobj.write(struct.pack("!Q", self.bytes_written))
                self.fileobj.seek(pos)
        self.close_mode.close(self.fileobj)
        self.closed = True

    def rewind(self):
        """
        Rewinds to the first block, clears the read buffer, and resets the counter. Will raise an exception if the
        underlying file object is not seekable.
        """
        assert self.mode == PZip.Mode.DECRYPT
        self.fileobj.seek(PZip.HEADER_SIZE + len(self.nonce))
        self.counter = 0
        self.buffer = b""

    # These are taken from Django, so this can be used in places where it expects a File object. They are also
    # generally useful to be able to stream a file with a specified chunk size.

    def multiple_chunks(self, chunk_size=None):
        return True

    def chunks(self, chunk_size=None):
        assert self.readable()
        try:
            # Django's File object resets to the beginning if possible, so we will too.
            self.rewind()
        except Exception:
            pass
        while True:
            # If chunk_size is not specified, it's more efficient to just yield blocks.
            data = self.read(chunk_size) if chunk_size else self.read_block()
            if not data:
                break
            yield data


def log(msg, *args):
    print(msg.format(*args), file=sys.stderr, flush=True)


def die(msg, *args, code=1):
    log(msg, *args)
    sys.exit(code)


def copy(infile, outfile, progress=None):
    """
    Copies infile to outfile in chunks, optionally updating a progress bar. Closes infile and outfile upon completion,
    if they are not interactive.
    """
    block_size = getattr(outfile, "block_size", PZip.DEFAULT_BLOCK_SIZE)
    while True:
        if hasattr(infile, "read_block"):
            chunk = infile.read_block()
        else:
            chunk = infile.read(block_size)
        if not chunk:
            break
        if hasattr(outfile, "write_block"):
            outfile.write_block(chunk)
        else:
            outfile.write(chunk)
        if progress:
            progress.update(len(chunk))
    if progress:
        progress.close()
    if not infile.isatty() and not isinstance(infile, io.BytesIO):
        infile.close()
    if not outfile.isatty() and not isinstance(outfile, io.BytesIO):
        outfile.close()


def get_files(filename, mode, key, is_password, options):
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
    key_args = {"password": key} if is_password else {"secret_key": key}
    if options.stdout:
        outfile = sys.stdout.buffer
    elif options.output:
        if not options.force and os.path.exists(options.output):
            die("%s: output file exists", options.output)
        outfile = open(options.output, "wb")
    if mode == PZip.Mode.ENCRYPT:
        if filename:
            infile = open(filename, "rb")
            # If not already specified, set output file to <filename>.pz.
            if not outfile:
                if not options.force and os.path.exists(filename + ".pz"):
                    die("%s: output file exists", filename + ".pz")
                outfile = open(filename + ".pz", "wb")
            # Progress total will be the size of the input file when encrypting.
            total = os.path.getsize(filename)
        else:
            infile = sys.stdin.buffer
            # If using STDIN and no output was specified, use STDOUT.
            if not outfile:
                outfile = sys.stdout.buffer
        # Wrap the output file in a PZip object.
        outfile = PZip(outfile, mode, **key_args, iterations=options.iterations, compress=not options.nozip)
    elif mode == PZip.Mode.DECRYPT:
        infile = PZip(filename or sys.stdin.buffer, mode, **key_args, decompress=not options.extract)
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
                    # Set the progress total to the (compressed) ciphertext size, since we aren't decompressing.
                    total = infile._ciphertext_size()
                if not options.force and os.path.exists(new_filename):
                    die("%s: output file exists", new_filename)
                outfile = open(new_filename, "wb")
            else:
                # Using STDIN and no output was specified, just dump to STDOUT.
                outfile = sys.stdout.buffer
    return infile, outfile, total


def print_info(filename, show_errors=False):
    try:
        fileobj = sys.stdin.buffer if filename == "-" else filename
        with PZip(fileobj, "rb") as f:
            key_bits = f.key_size * 8
            nonce_bits = f.nonce_size * 8
            info = "{}: PZip version {}; AES-{}; {}-bit nonce".format(filename, f.version, key_bits, nonce_bits)
            if f.compressed:
                info += "; compressed"
            if f.size:
                info += "; plaintext size {}".format(f.size)
            print(info)
    except FileNotFoundError:
        if show_errors:
            log("{}: file not found", filename)
    except IsADirectoryError:
        if show_errors:
            log("{}: is a directory", filename)
    except InvalidFile as e:
        if show_errors:
            log("{}: {}", filename, str(e))


def main(*args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-z", "--compress", action="store_true", default=False, help="force compression")
    parser.add_argument("-d", "--decompress", action="store_true", default=False, help="force decompression")
    parser.add_argument("-k", "--keep", action="store_true", default=False, help="keep input files")
    parser.add_argument("-c", "--stdout", action="store_true", default=False, help="write to stdout (implies -kq)")
    parser.add_argument("-f", "--force", action="store_true", default=False, help="overwrite existing output files")
    parser.add_argument("-a", "--auto", action="store_true", help="automatically generate and output a key")
    parser.add_argument("-e", "--key", help="encrypt/decrypt using key file")
    parser.add_argument("-p", "--password", help="encrypt/decrypt using password")
    parser.add_argument(
        "-i", "--iterations", type=int, default=PZip.DEFAULT_ITERATIONS, help="number of PBKDF2 iterations"
    )
    parser.add_argument("-o", "--output", help="specify outfile file name")
    parser.add_argument("-n", "--nozip", action="store_true", default=False, help="encrypt only, no compression")
    parser.add_argument("-x", "--extract", action="store_true", default=False, help="extract only, no decompression")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="no output")
    parser.add_argument(
        "-l", "--list", action="store_true", default=False, help="print information about the specified files"
    )
    parser.add_argument("files", metavar="file", nargs="*", help="files to encrypt or decrypt")
    options = parser.parse_args(args=args or None)
    if options.list:
        if not options.files:
            die("no files specified")
        for filename in options.files:
            print_info(filename, show_errors=not options.quiet)
        return
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
            log("{}: no such file", filename)
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
            is_password = False
        if options.password:
            log("-p ignored, using key file {}", options.key)
    elif options.password:
        key = options.password.encode("utf-8")
        is_password = True
        if options.auto:
            log("-a ignored, using password")
    elif options.auto:
        token = secrets.token_urlsafe(16)
        # Not strictly a problem, but make it easy to use as an argument to -p.
        while token.startswith("-"):
            token = secrets.token_urlsafe(16)
        log("encrypting with password: {}", token)
        key = token.encode("utf-8")
        is_password = True
    else:
        key = getpass.getpass("Password: ")
        if mode == PZip.Mode.ENCRYPT:
            verify = getpass.getpass("Verify: ")
            if verify != key:
                die("passwords did not match")
        key = key.encode("utf-8")
        is_password = True
    for filename in files:
        infile, outfile, total = get_files(filename, mode, key, is_password, options)
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
