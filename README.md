![CI](https://github.com/imsweb/pzip/workflows/CI/badge.svg?branch=master)

# PZip

PZip is an encrypted file format (with optional gzip compression), a command-line tool, and a Python file-like
interface.

## Installation

`pip install pzip`

## Command Line Usage

For a full list of options, run `pzip -h`. Basic usage is summarized below:

```
pzip --key keyfile sensitive_data.csv
pzip --key keyfile sensitive_data.csv.pz
```

Piping and outputting to stdout is also supported:

```
tar cf - somedir | pzip -z --key keyfile -o somedir.pz
pzip --key keyfile -c somedir.pz | tar xf -
```

PZip will generate an encryption key automatically, if you want:

```
pzip -a sensitive_data.csv
encrypting with password: HgHs4OIm4zGXkch6lTBIqg

pzip -p HgHs4OIm4zGXkch6lTBIqg sensitive_data.csv.pz
```

## Python Usage

```python
import os
from pzip import PZip

key = os.urandom(32)

with PZip("myfile.pz", PZip.Mode.ENCRYPT, key) as f:
    f.write(b"sensitive data")

with PZip("myfile.pz", PZip.Mode.DECRYPT, key) as f:
    print(f.read())
```

To encrypt using a password instead of a random key (and thus use PBKDF2 instead of HKDF):

```python
with PZip("myfile.pz", PZip.Mode.ENCRYPT, password=b"secret") as f:
    f.write(b"hello world")
```

For on-the-fly/streaming encryption, or writing to non-seekable files, you may pass in the length of the plaintext
that will be written in the PZip header. Alternately, if you don't wish to store the plaintext length in the header
for privacy reasons, you can pass `size=0`.

```python
plaintext = b"hello world"
with PZip(streaming_response, "wb", key, size=len(plaintext)) as f:
    f.write(plaintext)
```

## Encryption

PZip uses AES-GCM with 128-, 192-, or 256-bit (default) keys. Keys are derived using one of the following, based on
the source key material:

  * PBKDF2-SHA256 with a configurable iteration count (currently 200,000) if the key material is a password
  * HKDF-SHA256 if the key material is a random key

The PZip format is essentially an implemetation of the
[STREAM protocol](https://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf), a nonce-based OAE scheme.

A random 128-bit salt and 96-bit nonce (GCM IV) are generated by default for each file, but may also be supplied via
the Python interface for systems that can more strongly guarantee uniqueness. The key size, nonce size,
salt, iteration count (when using PBKDF2), and nonce/IV are stored in the PZip file header.

The ciphertext of a PZip file is split into some number of blocks. Each block is independently encrypted, is
prefixed with the length of the block, and has a 128-bit AES-GCM authentication tag appended to the end. The nonce for
each block (`Nb`) is calculated as follows, for block number `B` and original file nonce `N`:

  1. `B` is converted to a 32-bit big endian unsigned integer, and left padded with zero bits to be the same length as
     `N`.
  2. `N` is XOR-ed with `B` to get the block nonce, `Nb`.

## Compression

PZip optionally, and by default, compresses blocks (before encryption) using gzip. Compression level can be specified
using e.g. `compress=9`, or disabled by setting `compress=False`. PZip can stream out decrypted, but still compressed,
gzip data using `decompress=False` or the `--extract` option of the CLI.

## File Format

The PZip file format consists of a 40-byte header, followed by a variable-size nonce in plaintext, immediately followed
by one or more blocks. Each block begins with a 4-byte big endian unsigned integer block size `S`, followed by `S`
encrypted bytes, ending with a 16-byte authentication tag. The header is big endian, with the following fields/sizes:

  * File identification (magic), 4 bytes - `PZIP`
  * File format version, 1 byte - currently `\x01`
  * Flags, 1 byte:
    * Bit 0 (1): set when the file data is gzip-compressed
    * Bit 1 (2): set when the original key material was a password (use PBKDF2 instead of HKDF)
  * AES key size (in bytes), 1 byte - must be 16, 24, or 32
  * Nonce size (in bytes), 1 byte - 12 by default, may be larger
  * KDF salt (16 bytes)
  * KDF iterations (4 bytes, unsigned int/long) - currently unused if key material was not a password
  * Reserved for future use (4 bytes)
  * Plaintext length (8 bytes, unsigned long long) - optional, may be set to 0

Below is an example of a PZip file containing the plaintext "hello world", encrypted with a key derived from the string
"pzip", with no compression (for readability), and written as two blocks.

```
+-------------------------------------------------+------+----------+--------------------+
| Bytes                                           | Size | Value    | Description        |
+-------------------------------------------------+------+----------+--------------------+
| 50 5A 49 50                                     | 4    | PZIP     | File magic         |
| 01                                              | 1    | 1        | Version            |
| 02                                              | 1    | 2        | Flags              |
| 20                                              | 1    | 32       | Key size           |
| 0C                                              | 1    | 12       | Nonce size         |
| 08 6F 58 74 1C 96 B2 C2 7A 8D A2 71 64 22 70 2A | 16   | <salt>   | KDF salt           |
| 00 03 0d 40                                     | 4    | 200000   | KDF iterations     |
| 00 00 00 00                                     | 4    | 0        | Reserved           |
| 00 00 00 00 00 00 00 0B                         | 8    | 11       | Plaintext length   |
+-------------------------------------------------+------+----------+--------------------+
| 92 66 AE A5 5A 27 21 04 30 B6 08 6F             | 12   | <nonce>  | Nonce              |
+=================================================+======+==========+====================+
| 00 00 00 15                                     | 4    | 21       | Block 0 length     |
| 2D 9C 7F F9 66                                  | 5    | <hello>  | BLock 0 ciphertext |
| 5B 9C 44 4C 78 DA 54 E0 52 94 22 03 5C C1 FD 93 | 16   | <tag>    | Block 0 auth tag   |
+=================================================+======+==========+====================+
| 00 00 00 16                                     | 4    | 22       | Block 1 length     |
| 82 E0 78 BE FE A6                               | 6    | < world> | Block 1 ciphertext |
| 6C 5B A9 6A 06 69 79 E8 50 6D 27 C3 61 0B 2F 8E | 16   | <tag>    | Block 1 auth tag   |
+=================================================+======+==========+====================+
```

You can verify the above example in Python:

```python
>>> import binascii, io, pzip
>>> data = binascii.unhexlify(
...     "505A49500102200C086F58741C96B2C27A8DA2716422702A00030D4000000000000000000000000B9266"
...     "AEA55A27210430B6086F000000152D9C7FF9665B9C444C78DA54E0529422035CC1FD930000001682E078"
...     "BEFEA66C5BA96A066979E8506D27C3610B2F8E"
... )
>>> pzip.PZip(io.BytesIO(data), "rb", password=b"pzip").read()
b'hello world'
```

## FAQ

*Why does this exist?*

Nothing PZip does couldn't be done by chaining together existing tools - compressing with `gzip`, deriving a key and
encrypting with `openssl`, generating a MAC (if not using GCM), etc. But at that point, you're probably writing a
script to automate the process, tacking on bits of data here and there (or writing multiple files). PZip simply wraps
that in a nice package and documents a file format. Plus having a Python interface you can pretty much treat as a file
is super nice.

*Why not store filename?*

Storing the original filename has a number of security implications, both technical and otherwise. At a technical level,
PZip would need to ensure safe filename handling across all platforms with regards to path delimiters, encodings, etc.
Additionally, PZip was designed for a system where user-generated file attachments may contain sensitive information in
the filenames themselves. In reality, having a stored filename is of minimal use anyway, since the default behavior is
to append and remove a `.pz` suffix when encrypting/decrypting. If a `.pz` file was renamed, you would have a conflict
that would likely be resolved by using the actual filename (not the stored filename) anyway.
