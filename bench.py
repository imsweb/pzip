#!/usr/bin/env python

import io
import os
import time

import pzip


def bench():
    key = os.urandom(32)
    block_sizes = [
        # 2 ** 14,  # 16k
        # 2 ** 15,  # 32k
        # 2 ** 16,  # 64k
        2 ** 17,  # 128k
        2 ** 18,  # 256k
        2 ** 19,  # 512k
        2 ** 20,  # 1mb
        # 2 ** 22,  # 4mb
    ]
    for mb in (1, 20, 100):
        size = mb * 1024 * 1024
        for bs in block_sizes:
            data = os.urandom(bs)
            buf = io.BytesIO()
            for compress in (False, True):
                # Encrypt
                start = time.time()
                with pzip.open(buf, "wb", key=key, block_size=bs, compress=7) as f:
                    for i in range(size // bs):
                        f.write_block(data)
                elapsed = time.time() - start
                print(
                    "encrypt({}mb, block_size={}k, compress={}): {}".format(
                        mb, bs // 1024, compress, elapsed
                    )
                )
                # Decrypt
                start = time.time()
                with pzip.open(buf, "rb", key=key) as f:
                    for block in f.chunks():
                        assert len(block) == bs
                elapsed = time.time() - start
                print(
                    "decrypt({}mb, block_size={}k, compress={}): {}\n".format(
                        mb, bs // 1024, compress, elapsed
                    )
                )


if __name__ == "__main__":
    bench()
