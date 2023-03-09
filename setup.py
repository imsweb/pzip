import os
import re

from setuptools import find_packages, setup

with open("README.md", "r") as readme:
    long_description = readme.read()

with open(os.path.join("pzip", "__init__.py"), "r") as src:
    version = re.match(r'.*__version__ = "(.*?)"', src.read(), re.S).group(1)

setup(
    name="pzip",
    version=version,
    description="Crytographically secure file compression.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Dan Watson",
    author_email="watsond@imsweb.com",
    url="https://github.com/imsweb/pzip",
    license="MIT",
    packages=find_packages(),
    install_requires=["cryptography"],
    extras_require={
        "deflate": ["deflate"],
        "tqdm": ["tqdm"],
        "all": ["deflate", "tqdm"],
    },
    entry_points={"console_scripts": ["pzip=pzip.cli:main"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Archiving :: Compression",
    ],
)
