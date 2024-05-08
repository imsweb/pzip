import functools
import gzip
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pzip
import pzip.base
from pzip.cli import main

TEST_SECRET_KEY = os.urandom(32)

# Mostly for compat with already-written tests, but also a way to do a default key.
TestPZip = functools.partial(pzip.open, key=pzip.Key(TEST_SECRET_KEY))

# Speed up the password tests.
pzip.base.DEFAULT_ITERATIONS = 1


class PZipTests(unittest.TestCase):
    def test_round_trip(self):
        buf = io.BytesIO()
        plaintext = b"Hello, world!\n" * 1000
        with TestPZip(buf, "wb") as f:
            f.write(plaintext)
        self.assertLess(len(buf.getvalue()), len(plaintext))
        with TestPZip(buf, "rb") as f:
            self.assertEqual(f.read(), plaintext)
            self.assertEqual(f.plaintext_size(), len(plaintext))

    def test_bad_key(self):
        buf = io.BytesIO()
        plaintext = b"message"
        for compress in (True, False):
            with TestPZip(buf, "wb", key="goodkey", compress=compress) as f:
                f.write(plaintext)
            self.assertTrue(f.kdf, pzip.KeyDerivation.PBKDF2_SHA256)
            with self.assertRaises(pzip.InvalidFile):
                TestPZip(buf, "rb", key=b"badkey").read_block()

    def test_no_compression(self):
        buf = io.BytesIO()
        plaintext = b"My voice is my passport. Verify me."
        with TestPZip(buf, "wb", compress=False) as f:
            f.write(plaintext)
        with TestPZip(buf, "rb") as f:
            self.assertEqual(f.ciphertext_size(), len(plaintext))
            self.assertEqual(f.read(), plaintext)

    def test_integrity(self):
        plaintext = os.urandom(1024) * 128
        for compress in (False, True):
            buf = io.BytesIO()
            with TestPZip(buf, "wb", compress=compress) as f:
                f.write(plaintext)
            # Alter some bytes in the first encrypted block.
            contents = buf.getbuffer()
            for i in range(f.block_start + 4, f.block_start + 14):
                contents[i] ^= 128
            # The file should have a valid header, but fail upon reading/authentication.
            with TestPZip(io.BytesIO(contents), "rb") as f:
                with self.assertRaises(pzip.InvalidFile):
                    # Cover both compression integrity failures during streaming reads,
                    # and authentication failures.
                    f.read(200 if compress else None)

    def test_iter_read_lines(self):
        buf = io.BytesIO()
        plaintext = b"Hello, world!\n"
        for compress in (True, False):
            with TestPZip(buf, "wb", compress=compress) as f:
                f.write(plaintext * 100)
            with TestPZip(buf, "rb") as f:
                for line in f:
                    self.assertEqual(line, plaintext)

    def test_bad_headers(self):
        with self.assertRaises(pzip.InvalidFile):
            TestPZip(io.BytesIO(b"PZ"), "rb")
        bad_headers = [
            b"PZ",  # bad magic
            b"\xb6\x9e\x02",  # bad version
            b"\xb6\x9e\x01\x00\x02",  # bad algorithm
            b"\xb6\x9e\x01\x00\x01\x03",  # bad kdf
            b"\xb6\x9e\x01\x00\x01\x01\x02",  # bad compression
        ]
        for bad in bad_headers:
            pad = b"\x00" * (pzip.PZip.HEADER_SIZE - len(bad))
            with self.assertRaises(pzip.InvalidFile):
                TestPZip(io.BytesIO(bad + pad), "rb")

    def test_modes(self):
        with self.assertRaises(ValueError):
            TestPZip(io.BytesIO(), "a")
        buf = io.BytesIO()
        with TestPZip(buf, "wb") as f:
            f.write(b"Hello world!")
            self.assertTrue(f.writable())
            self.assertFalse(f.readable())
            self.assertFalse(f.seekable())
            with self.assertRaises(NotImplementedError):
                f.read()
        # Test that mode defaults to "rb"
        with pzip.open(buf) as f:
            self.assertIsInstance(f, pzip.PZipReader)
        with TestPZip(buf, "rb") as f:
            self.assertTrue(f.readable())
            self.assertFalse(f.writable())
            self.assertFalse(f.seekable())
            with self.assertRaises(NotImplementedError):
                f.write(b"")

    def test_close_modes(self):
        buf = io.BytesIO()
        TestPZip(buf, "wb", close=pzip.Close.ALWAYS).close()
        self.assertTrue(buf.closed)
        buf = io.BytesIO()
        TestPZip(buf, "wb", close=pzip.Close.NEVER).close()
        self.assertFalse(buf.closed)
        with TestPZip(buf, "wb", close=pzip.Close.REWIND) as f:
            f.write(b"advance that pointer")
        self.assertFalse(buf.closed)
        self.assertEqual(buf.tell(), 0)

    def test_chunked_reads(self):
        buf = io.BytesIO()
        plaintext = b"Hello, world!\n"
        num = 1000
        for compress in (True, False):
            with TestPZip(buf, "wb", compress=compress) as f:
                f.write(plaintext * num)
            with TestPZip(buf, "rb") as f:
                chunks = list(f.chunks(len(plaintext)))
                self.assertEqual(len(chunks), num)
                self.assertEqual(b"".join(chunks), plaintext * num)

    def test_peek_rewind(self):
        buf = io.BytesIO()
        plaintext = b"Hello, world!\n" * 1000
        with TestPZip(buf, "wb") as f:
            f.write(plaintext)
        with self.assertRaises(pzip.InvalidFile):
            # Peeking with a bad key should raise InvalidFile immediately.
            TestPZip(buf, "rb", key=b"badkey", peek=True)
        buf.seek(0)
        with TestPZip(buf, "rb", peek=True) as f:
            self.assertEqual(f.read(), plaintext)
            f.rewind()
            self.assertEqual(f.read(), plaintext)

    def test_tags(self):
        buf = io.BytesIO()
        plaintext = b"Hello, world!\n" * 100
        with TestPZip(buf, "wb") as f:
            f.tags[pzip.Tag.FILENAME] = b"hello.txt"
            f.tags[pzip.Tag.COMMENT] = b"this is a test"
            f.write(plaintext)
        with TestPZip(buf, "rb") as f:
            self.assertTrue(f.tags[pzip.Tag.FILENAME], b"hello.txt")
            self.assertTrue(f.tags[pzip.Tag.COMMENT], b"this is a test")


class redirect:
    def __init__(self, name, data=b""):
        self.name = name
        self.buf = io.BytesIO(data) if isinstance(data, bytes) else io.StringIO(data)

    def __enter__(self):
        self.fd = getattr(sys, self.name)
        if isinstance(self.buf, io.BytesIO):
            fake = MagicMock()
            fake.buffer = self.buf
        else:
            fake = self.buf
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
            keyfile = os.path.join(root, "keyfile")
            with open(keyfile, "wb") as f:
                f.write(os.urandom(32))
            name = os.path.join(root, "tempfile")
            with open(name, "wb") as f:
                f.write(plaintext)
            # Use 1 iteration for speed.
            main("-q", name)
            self.assertFalse(os.path.exists(name))
            self.assertTrue(os.path.exists(name + ".pz"))
            # Check the --list option while we have a .pz file written out.
            with redirect("stdout", "") as stdout:
                main("-l", name + ".pz")
            self.assertEqual(
                stdout.getvalue().strip(),
                "{}: PZip version 1 | AES-GCM-256 | PBKDF2-SHA256 | GZIP".format(
                    name + ".pz"
                ),
            )
            main("-q", name + ".pz")
            self.assertTrue(os.path.exists(name))
            self.assertFalse(os.path.exists(name + ".pz"))
            # Test encryption using a keyfile.
            main("-q", "--key", keyfile, name)
            main("-q", "--key", keyfile, name + ".pz")
            with open(name, "rb") as f:
                self.assertEqual(f.read(), plaintext)
            main("-q", "-o", name + ".enc", name)
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
                main("-z", "-c", "-")
        ciphertext = stdout.getvalue()
        with redirect("stdout") as stdout:
            with redirect("stdin", ciphertext):
                # Decrypt from STDIN, write to STDOUT.
                main("-d", "-c")
        self.assertEqual(plaintext, stdout.getvalue())

    def test_auto_password(self):
        plaintext = "ƒøôβå®".encode("utf-8")
        with tempfile.TemporaryDirectory() as root:
            name = os.path.join(root, "autofile")
            with open(name, "wb") as f:
                f.write(plaintext)
            with redirect("stderr", "") as stderr:
                main("-q", "-a", name)
                password = stderr.getvalue().split(": ")[-1].strip()
                self.assertFalse(password.startswith("-"))
            main("-q", "-p", password, name + ".pz")
            with open(name, "rb") as f:
                self.assertEqual(f.read(), plaintext)


if __name__ == "__main__":
    unittest.main()
