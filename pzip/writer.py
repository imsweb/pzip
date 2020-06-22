import struct

from .base import BlockFlag, Compression, Flag, KeyMaterial, PZip


def encode_int(num):
    """
    Space-efficient integer encoding for tags.
    """
    if num < 2 ** 8:
        return struct.pack("!B", num)
    elif num < 2 ** 16:
        return struct.pack("!H", num)
    elif num < 2 ** 32:
        return struct.pack("!L", num)
    else:
        return struct.pack("!Q", num)


class PZipWriter(PZip):
    def __init__(self, fileobj, key, nonce=None, block_size=None, append_length=True, compress=None, **kwargs):
        key = KeyMaterial.resolve(key)
        super().__init__(fileobj, **kwargs)
        # Set the KDF that was used, if any.
        self.kdf = key.kdf
        # Set the compression algorithm and level, if any.
        self.compression, self.compresslevel = Compression.resolve(compress)
        # Let the key/KDF set any tags it needs (salt, iterations, info).
        self.tags.update(key.get_tags())
        # Let the algorithm set any tags it needs (nonce).
        self.tags.update(self.algorithm.get_tags(nonce=nonce))
        self.block_size = block_size or self.DEFAULT_BLOCK_SIZE
        if append_length:
            self.flags |= Flag.APPEND_LENGTH
        # Keep track of how many plaintext bytes we're written.
        self.bytes_written = 0
        # Initialize the cipher.
        self.initialize(key)
        # This is set when writing the header (lazily).
        self.block_start = None

    def writable(self):
        return True

    def write_header(self):
        """
        Writes the PZip header and tags.
        """
        tag_data = b""
        num_tags = 0
        for tag, data in self.tags.items():
            if data is None:
                continue
            if tag < 0:
                data = encode_int(data)
            tag_data += struct.pack("!bB", tag, len(data)) + data
            num_tags += 1
        self.fileobj.write(
            struct.pack(
                self.HEADER_FORMAT,
                self.MAGIC,
                self.version,
                self.flags,
                self.algorithm,
                self.kdf,
                self.compression,
                num_tags,
            )
        )
        if num_tags and tag_data:
            self.fileobj.write(tag_data)
        # This isn't particularly useful when writing files, but is for testing.
        self.block_start = self.HEADER_SIZE + len(tag_data)

    def write_block(self, plaintext, last=False):
        """
        Writes a block of plaintext including the block header, after compressing and encrypting it.
        """
        if self.block_start is None:
            self.write_header()
        if not plaintext:
            ciphertext = b""
        else:
            self.bytes_written += len(plaintext)
            data = self.compression.compress(plaintext, self.compresslevel)
            ciphertext = self.cipher.encrypt(self.next_nonce(), data, None)
        # The first 8 bits of the header are flags, the last 24 bits are the length.
        assert len(ciphertext) < 2 ** 24
        header = bytearray(struct.pack("!L", len(ciphertext)))
        header[0] = BlockFlag.LAST if last else 0
        self.fileobj.write(header)
        self.fileobj.write(ciphertext)

    def write(self, data):
        """
        Buffers an arbitrary amount of data to be written using write_block. Blocks will not be written until the
        buffer is at least block_size bytes, or the file is closed.
        """
        self.buffer.extend(data)
        block_size = self.block_size  # Work around black's silly slice spacing.
        while len(self.buffer) >= block_size:
            self.write_block(bytes(self.buffer[:block_size]))
            del self.buffer[:block_size]
        return len(data)

    def flush(self, last=False):
        """
        Writes any buffered data into a new block. If `last` is `True`, an empty block will be written with the
        `BlockFlag.LAST` bit set, even if there is no data buffered.
        """
        if self.buffer or last:
            self.write_block(bytes(self.buffer), last=last)
        self.buffer.clear()

    def close(self):
        """
        Write any remaining buffered data out, making sure the last block written has the `BlockFlag.LAST` bit set.
        If `Flag.APPEND_LENGTH` is set, also append the plaintext length to the end of the file.
        """
        if not self.closed:
            self.flush(last=True)
            if self.append_length:
                self.fileobj.write(struct.pack("!Q", self.bytes_written))
        super().close()
