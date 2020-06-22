import io
import struct

from cryptography.exceptions import InvalidTag

from .base import Algorithm, BlockFlag, Compression, Flag, InvalidFile, KeyDerivation, PZip, Tag


class PZipReader(PZip):
    def __init__(self, fileobj, key=None, decompress=True, peek=False, **kwargs):
        super().__init__(fileobj, **kwargs)
        # Whether we should decompress data while reading. Set to False to stream out gzip blocks.
        self.decompress = decompress
        # Keep track of how many plaintext bytes were read (N/A when decompress=False).
        self.bytes_read = 0
        # Set after we read the last block.
        self.eof = False
        # Remember where the first block starts, to be able to rewind the stream if possible.
        self.block_start = None
        self.read_header()
        if key:
            self.initialize(key)
        if peek:
            self.buffer.extend(self.read_block())

    def readable(self):
        return True

    def read_header(self):
        """
        Reads the PZip header and tags.
        """
        data = self.fileobj.read(self.HEADER_SIZE)
        if len(data) < self.HEADER_SIZE:
            raise InvalidFile("Invalid PZip header.")
        (magic, self.version, flags, algorithm, kdf, compression, num_tags) = struct.unpack(self.HEADER_FORMAT, data)
        if magic != self.MAGIC:
            raise InvalidFile("File is not a PZip archive.")
        if self.version != 1:
            raise InvalidFile("Invalid or unknown file version ({}).".format(self.version))
        try:
            self.flags = Flag(flags)
            self.algorithm = Algorithm(algorithm)
            self.kdf = KeyDerivation(kdf)
            self.compression = Compression(compression)
        except ValueError as e:
            raise InvalidFile("Invalid header field.") from e
        num_bytes = self.read_tags(num_tags)
        self.block_start = self.HEADER_SIZE + num_bytes

    def read_tags(self, num_tags):
        """
        Reads tag data and returns how much data was read.
        """
        num_bytes = 0
        for num in range(num_tags):
            header = self.fileobj.read(2)
            if len(header) < 2:
                raise InvalidFile("Error reading tag #{} header.".format(num))
            tag, length = struct.unpack("!bB", header)
            data = self.fileobj.read(length)
            if len(data) < length:
                raise InvalidFile("Error reading tag #{} data (tag={}).".format(num, tag))
            if tag < 0:
                # High/sign bit set means interpret as an unsigned number.
                fmt = {1: "!B", 2: "!H", 4: "!L", 8: "!Q"}
                if length not in fmt:
                    raise InvalidFile("Invalid integer size ({}) for tag #{} (tag={}).".format(length, num, tag))
                data = struct.unpack(fmt[length], data)[0]
            try:
                tag = Tag(tag)
            except ValueError:
                # TODO: log this? make a "strict" option? just ignore?
                print("Unknown tag: {}".format(tag))
            self.tags[tag] = data
            num_bytes += length + 2
        return num_bytes

    def read_block(self):
        """
        Reads a full block of ciphertext, including the block header (size), and decrypts/decompresses it to return
        a block of plaintext. Raises InvalidFile if the block could not be authenticated.
        """
        if self.eof:
            return b""
        block_header = self.fileobj.read(4)
        if not block_header:
            self.eof = True
            return b""
        if len(block_header) != 4:
            raise InvalidFile("Error reading header for block {}.".format(self.counter))
        block_flags = BlockFlag(block_header[0])
        block_size = int.from_bytes(block_header[1:], "big")
        if block_size:
            ciphertext = self.fileobj.read(block_size)
            if len(ciphertext) < block_size:
                raise InvalidFile("Error reading block {} data.".format(self.counter))
            try:
                plaintext = self.cipher.decrypt(self.next_nonce(), ciphertext, None)
            except InvalidTag as e:
                raise InvalidFile() from e
            if self.decompress:
                plaintext = self.compression.decompress(plaintext)
                self.bytes_read += len(plaintext)
        else:
            plaintext = b""
        if BlockFlag.LAST in block_flags:
            if self.append_length:
                size_check = self.fileobj.read(8)
                if len(size_check) != 8:
                    raise InvalidFile("Error reading appended plaintext length.")
                size_check = int.from_bytes(size_check, "big")
                if self.decompress and self.bytes_read != size_check:
                    raise InvalidFile("Plaintext lengths do not match.")
            self.eof = True
        return plaintext

    def read(self, size=-1):
        """
        Reads an arbitrary amount of data, buffering any unread bytes of the last read block.
        """
        read_all = size is None or size < 0
        while read_all or (len(self.buffer) < size):
            block = self.read_block()
            if not block:
                break
            self.buffer.extend(block)
        try:
            return bytes(self.buffer) if read_all else bytes(self.buffer[:size])
        finally:
            # Trim how much we returned off the front of the buffer.
            if read_all:
                self.buffer.clear()
            else:
                del self.buffer[:size]

    def rewind(self):
        """
        Rewinds to the first block, clears the read buffer, and resets the counter. Will raise an exception if the
        underlying file object is not seekable.
        """
        self._checkClosed()
        if not self.block_start:
            raise io.UnsupportedOperation("Cannot rewind; stream is not seekable.")
        self.fileobj.seek(self.block_start)
        self.bytes_read = 0
        self.counter = 0
        self.eof = False
        self.buffer.clear()

    # These are taken from Django, so this can be used in places where it expects a File object. They are also
    # generally useful to be able to stream a file with a specified chunk size.

    def multiple_chunks(self, chunk_size=None):
        return True

    def chunks(self, chunk_size=None):
        self._checkClosed()
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

    def plaintext_size(self):
        """
        Calculates the total plaintext size using the most efficient method available (if any).
        """
        if self.eof:
            return self.bytes_read
        elif self.append_length:
            self._checkClosed()
            old_pos = self.fileobj.tell()
            self.fileobj.seek(-8, 2)
            size_check = int.from_bytes(self.fileobj.read(8), "big")
            self.fileobj.seek(old_pos)
            return size_check
        elif self.compression.value == 0:
            return self.ciphertext_size()
        return None

    def ciphertext_size(self):
        """
        Calculates the total ciphertext size, minus block headers and authentication tags. Will raise an exception if
        the underlying file object is not seekable.
        """
        self._checkClosed()
        # Remember where we were, so we can reset the file position when we're done.
        old_pos = self.fileobj.tell()
        # Start reading at the first block header.
        self.fileobj.seek(self.block_start)
        total = 0
        while True:
            block_header = self.fileobj.read(4)
            if not block_header:
                # No more blocks, reset the file position and return the total size thus far.
                self.fileobj.seek(old_pos)
                return total
            block_flags = BlockFlag(block_header[0])
            block_size = int.from_bytes(block_header[1:], "big")
            total += block_size - self.algorithm.tag_length()
            if BlockFlag.LAST in block_flags:
                self.fileobj.seek(old_pos)
                return total
            # Seek forward block_size bytes.
            self.fileobj.seek(block_size, 1)
