# PZip

PZip is an encrypted file format (with optional compression), a command-line tool, and a Python file-like interface.

## Installation

PZip is available on [PyPI](https://pypi.org/project/pzip/):

`pip install pzip`


## Command Line Usage

For a full list of options, run `pzip -h`. Basic usage is summarized below:

```bash
pzip --key keyfile sensitive_data.csv
pzip --key keyfile sensitive_data.csv.pz
```

Piping and outputting to stdout is also supported:

```bash
tar cf - somedir | pzip -z --key keyfile -o somedir.pz
pzip --key keyfile -c somedir.pz | tar xf -
```

PZip will generate an encryption key automatically, if you want:

```bash
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

To encrypt using a password instead of a random key (and thus use PBKDF2 instead of HKDF for key derivation):

```python
with pzip.open("myfile.pz", "wb", key=pzip.Password("secret")) as f:
    f.write(b"hello world")
```

By default, PZip will append the total plaintext length to the end of the file, both as a final integrity check, and a way for applications to quickly get the original file size. However, you can disable this by passing `append_length=False` when opening a file/stream for writing:

```python
with pzip.open(output_stream, "wb", key=secret, append_length=False) as f:
    f.write(plaintext)
```
