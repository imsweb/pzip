import re

from setuptools import setup

with open("README.md", "r") as readme:
    long_description = readme.read()

with open("pzip.py", "r") as src:
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
    py_modules=["pzip"],
    install_requires=["cryptography", "tqdm"],
    entry_points={"console_scripts": ["pzip=pzip:main"]},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Archiving :: Compression",
    ],
)
