![CI](https://github.com/imsweb/pzip/workflows/CI/badge.svg?branch=master)

# PZip

PZip is an encrypted file format (with optional gzip compression), a command-line tool, and a Python file-like interface.

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
import os, pzip

key = pzip.Key(os.urandom(32))

with pzip.open("myfile.pz", "wb", key=key) as f:
    f.write(b"sensitive data")

with pzip.open("myfile.pz", "rb", key=key) as f:
    print(f.read())
```

To encrypt using a password instead of a random key (and thus use PBKDF2 instead of HKDF):

```python
with pzip.open("myfile.pz", "wb", key=pzip.Password("secret")) as f:
    f.write(b"hello world")
```

For on-the-fly/streaming encryption, or writing to non-seekable files, you may pass in the length of the plaintext that will be written in the PZip header. Alternately, if you don't wish to store the plaintext length in the header for privacy reasons, you can pass `size=0`.

```python
plaintext = b"hello world"
with pzip.open(streaming_response, "wb", key, size=len(plaintext)) as f:
    f.write(plaintext)
```

## Encryption

See the [Encryption docs](encryption.md) for more information.

## File Format

See the [File Format docs](format.md) for more information.

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
