# File Format

## Overview

The PZip file format consists of an 8-byte header, followed by a set of tags, followed by one or more encrypted blocks. Each block is prefixed with its length and flags, and has an authentication tag appended to the end.


## Header

The header is 8 bytes, arranged as follows:

```
+-----+-----+-----+-----+-----+-----+-----+-----+
| ID1 | ID2 | VER | FLG | ALG | KDF | CMP | NUM |
+-----+-----+-----+-----+-----+-----+-----+-----+
```

* `ID1`/`ID2` is always `\x86\x9E` (or `¶ž`)
* `VER` is the format version, currently 1
* `FLG` is a bitfield of flags
* `ALG` is the encryption algorithm used
* `KDF` is the key derivation function used
* `CMP` is the compression method used
* `NUM` is the number of tags immediately following the header

### Flags

Bit  | Value   | Description
:--- | :------ | :--------------------------------------------------------------------------------
0    | 1       | Whether the file has an 8-byte (big-endian) plaintext length appended to the end

### Algorithms

Value   | Algorithm
:------ | :-----------
1       | AES-GCM-256

### Key Derivation Functions

Value   | KDF
:------ | :-----------
0       | Raw (no KDF)
1       | HKDF-SHA256
2       | PBKDF2-SHA256

### Compression Methods

Value   | KDF
:------ | :-----------
0       | No compression
1       | GZIP


## Tags

Tags are used to specify data used in encryption, key derivation, compression, or just user-supplied data. Each tag consists of a two-byte header specifying the signed tag number (-128 to 127) and unsigned tag length (0-255):

```
+-----+-----+-------------------+
| TAG | LEN | ... LEN bytes ... |
+-----+-----+-------------------+
```

Negative tags are interpreted as big-endian integer values of whatever `LEN` is specified (i.e. 32-bit for `LEN=4`). Positive tag numbers are simply interpreted as bytestrings.

### Tag Values

Tag | Description
:-- | :----------
1   | Nonce
2   | KDF salt
-3  | KDF iteration count
4   | KDF info parameter
5   | Filename
6   | Application
7   | MIME type
127 | Comment


## Encrypted Blocks

PZip files are encrypted in some number of variable-length blocks. By default, PZip uses a block size of 2^18 (256 KB), but this may vary per file, or even per block. Each block is prefixed with a 4-byte header. The first byte is a bitfield of flags:

### Block Flags

Bit  | Value | Description
:--- | :---- | :--------------------------------------------------------------------------------
7    | 128   | Set for last block of the file

The remaining 3 bytes is a 24-bit big endian block size, so blocks have an upper size limit of about 16 MB. Each block is also appended with a 16-byte (128-bit) authentication tag (included in the block size). The remainder of the block is encrypted (and potentially compressed) ciphertext.


## Sample File

Below is a descriptive breakdown of a PZip file containing the bytestring "Hello, world!", encrypted with a key derived using PBKDF2 from the password "pzip":

Bytes (hex) | Description
:---------- | :----------
B6 9E 01 01 01 02 00 03  | Header: Version 1, APPEND_LENGTH, AES-GCM-256, PBKDF2-SHA256, no compression, 3 tags
02 20 | Tag 2 (KDF_SALT), length 32
07 4D 65 15 16 E6 8F 05 61 B5 5B 81 37 6F 9E 38 C6 0F 0C DA EA BE 1C BE FC AC 0C 41 4C 45 41 A2 | PBKDF2 salt
FD 04 | Tag -3 (KDF_ITERATIONS)
00 03 0D 40 | 200,000 iterations
01 0C | Tag 1 (NONCE), length 12
53 FB D2 4B F5 D4 28 38 16 13 5F CF | AES-GCM Nonce
80 00 00 1D | Block header: LAST_BLOCK, length 29
BF 3E C0 AC FC 98 9B 11 09 9F 4A 40 E3 | "Hello, world!" (encrypted)
AD 5D A7 58 62 F9 A2 B1 7A 91 5C 79 D2 E6 C4 B2 | AES-GCM authentication tag
00 00 00 00 00 00 00 0D | Appended plaintext length (13)


You can verify the above example in Python:

```python
import binascii, io, pzip
data = binascii.unhexlify('B69E0101010200030220074D651516E68F0561B5'
    '5B81376F9E38C60F0CDAEABE1CBEFCAC0C414C4541A2FD0400030D40010C53'
    'FBD24BF5D4283816135FCF8000001DBF3EC0ACFC989B11099F4A40E3AD5DA7'
    '5862F9A2B17A915C79D2E6C4B2000000000000000D'
)
pzip.open(io.BytesIO(data), "rb", key="pzip").read()
```
