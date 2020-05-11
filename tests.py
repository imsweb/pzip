import io
import os
import unittest

from pzip import InvalidFile, PZip

TEST_SECRET_KEY = os.urandom(32)


class TestPZip(PZip):
    # Keep the unit tests fast.
    DEFAULT_ITERATIONS = 1

    def default_key(self):
        return TEST_SECRET_KEY


class PZipTests(unittest.TestCase):
    def test_round_trip(self):
        buf = io.BytesIO()
        plaintext = b"Hello, world!\n" * 1000
        with TestPZip(buf, PZip.Mode.ENCRYPT) as f:
            f.write(plaintext)
        self.assertEqual(f.size, len(plaintext))
        with TestPZip(buf, PZip.Mode.DECRYPT) as f:
            self.assertEqual(f.read(), plaintext)

    def test_bad_key(self):
        buf = io.BytesIO()
        plaintext = b"message"
        for compress in (True, False):
            with TestPZip(buf, PZip.Mode.ENCRYPT, b"goodkey", compress=compress) as f:
                f.write(plaintext)
            with self.assertRaises(InvalidFile):
                TestPZip(buf, PZip.Mode.DECRYPT, b"badkey")

    def test_no_compression(self):
        buf = io.BytesIO()
        plaintext = b"My voice is my passport. Verify me."
        with TestPZip(buf, PZip.Mode.ENCRYPT, compress=False) as f:
            f.write(plaintext)
        self.assertEqual(f.size, len(plaintext))
        self.assertEqual(len(buf.getvalue()), f.size + f.header_size + 16)
        with TestPZip(buf, PZip.Mode.DECRYPT) as f:
            self.assertEqual(f.read(), plaintext)

    def test_integrity(self):
        buf = io.BytesIO()
        plaintext = os.urandom(1024)
        with TestPZip(buf, PZip.Mode.ENCRYPT, compress=False) as f:
            f.write(plaintext)
        # Alter a byte after the initial nonce check value.
        contents = buf.getbuffer()
        contents[f.header_size + 20] = contents[f.header_size + 20] ^ 128
        # The file should have a valid header and nonce check, but fail upon reading/authentication.
        with TestPZip(io.BytesIO(contents), PZip.Mode.DECRYPT) as f:
            with self.assertRaises(InvalidFile):
                f.read()

    def test_iter_read(self):
        buf = io.BytesIO()
        plaintext = os.urandom(1024) * 1024
        with TestPZip(buf, PZip.Mode.ENCRYPT, compress=False) as f:
            f.write(plaintext)
        with TestPZip(buf, PZip.Mode.DECRYPT) as f:
            self.assertEqual(b"".join(chunk for chunk in f), plaintext)

    def test_bad_header(self):
        with self.assertRaises(InvalidFile):
            TestPZip(io.BytesIO(), PZip.Mode.DECRYPT)

    def test_modes(self):
        with self.assertRaises(ValueError):
            TestPZip(io.BytesIO(), "a")
        buf = io.BytesIO()
        with TestPZip(buf, "wb") as f:
            f.write(b"Hello world!")
            self.assertTrue(f.writable())
            self.assertFalse(f.readable())
            self.assertFalse(f.seekable())
            with self.assertRaises(io.UnsupportedOperation):
                f.read()
        with TestPZip(buf, "rb") as f:
            self.assertTrue(f.readable())
            self.assertFalse(f.writable())
            self.assertFalse(f.seekable())
            with self.assertRaises(io.UnsupportedOperation):
                f.write(b"")


if __name__ == "__main__":
    unittest.main()
