## 1.2.0 (2024-11-08)

* Switched to [uv](https://github.com/astral-sh/uv)
* Dropped Python 3.8 support, test on Python 3.13
* Renamed `--nozip` to `--nocompress` in case we ever support non-zlib compression
* Addressed an issue where `isatty` was potentially called on a file object being
  garbage-collected (found in testing with 3.13)


## 1.1.0 (2024-05-09)

* Increased default PBKDF2 iterations to 600,000
* Changed `DEFAULT_BLOCK_SIZE` from 256k to 128k
* Removed the `tqdm` optional requirement
* Switched to `pyproject.toml`, [hatchling](https://hatch.pypa.io/) for builds, and
  [ruff](https://github.com/astral-sh/ruff) for formatting and linting


## 1.0.0 (2023-03-09)

* Initial release
