import gzip
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from pzip import InvalidFile, PZip, main

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
        self.assertLess(len(buf.getvalue()), f.size)
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
        plaintext = os.urandom(1024) * 128
        for compress in (False, True):
            buf = io.BytesIO()
            with TestPZip(buf, PZip.Mode.ENCRYPT, compress=compress) as f:
                f.write(plaintext)
            # Alter some bytes after the initial nonce check value.
            contents = buf.getbuffer()
            for i in range(50, 100):
                contents[f.header_size + i] = contents[f.header_size + i] ^ 128
            # The file should have a valid header and nonce check, but fail upon reading/authentication.
            with TestPZip(io.BytesIO(contents), PZip.Mode.DECRYPT) as f:
                with self.assertRaises(InvalidFile):
                    # Cover both compression integrity failures during streaming reads, and authentication failures.
                    f.read(200 if compress else None)

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

    def test_close_modes(self):
        buf = io.BytesIO()
        TestPZip(buf, PZip.Mode.ENCRYPT, close=PZip.Close.ALWAYS).close()
        self.assertTrue(buf.closed)
        buf = io.BytesIO()
        TestPZip(buf, PZip.Mode.ENCRYPT, close=PZip.Close.NEVER).close()
        self.assertFalse(buf.closed)
        with TestPZip(buf, PZip.Mode.ENCRYPT, close=PZip.Close.REWIND) as f:
            f.write(b"advance that pointer")
        self.assertFalse(buf.closed)
        self.assertEqual(buf.tell(), 0)


class redirect:
    def __init__(self, name, data=b""):
        self.name = name
        self.buf = io.BytesIO(data)

    def __enter__(self):
        self.fd = getattr(sys, self.name)
        fake = MagicMock()
        fake.buffer = self.buf
        setattr(sys, self.name, fake)
        return self.buf

    def __exit__(self, exc_type, exc_value, traceback):
        setattr(sys, self.name, self.fd)


class CommandLineTests(unittest.TestCase):
    @patch("getpass.getpass")
    def test_encrypt_decrypt(self, getpass):
        getpass.return_value = "secret"
        plaintext = b"I am a real file."
        with tempfile.TemporaryDirectory() as root:
            name = os.path.join(root, "tempfile")
            with open(name, "wb") as f:
                f.write(plaintext)
            # Use 1 iteration for speed.
            main("-q", "-i1", name)
            self.assertFalse(os.path.exists(name))
            self.assertTrue(os.path.exists(name + ".pz"))
            main("-q", name + ".pz")
            self.assertTrue(os.path.exists(name))
            self.assertFalse(os.path.exists(name + ".pz"))
            with open(name, "rb") as f:
                self.assertEqual(f.read(), plaintext)
            main("-q", "-i1", "-o", name + ".enc", name)
            main("-q", "-x", name + ".enc")
            self.assertTrue(os.path.exists(name + ".gz"))
            with gzip.open(name + ".gz") as gz:
                self.assertTrue(gz.read(), plaintext)
            os.remove(name + ".gz")

    @patch("getpass.getpass")
    def test_stdin_stdout(self, getpass):
        getpass.return_value = "secret"
        plaintext = "ƒøôβå®".encode("utf-8")
        with redirect("stdout") as stdout:
            with redirect("stdin", plaintext):
                # Encrypt from STDIN, write to STDOUT. Use 1 iteration for speed.
                main("-z", "-i1", "-c", "-")
        ciphertext = stdout.getvalue()
        with redirect("stdout") as stdout:
            with redirect("stdin", ciphertext):
                # Decrypt from STDIN, write to STDOUT.
                main("-d", "-c")
        self.assertEqual(plaintext, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
