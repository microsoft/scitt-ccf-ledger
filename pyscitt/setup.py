# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from os import path

from setuptools import find_packages, setup

PACKAGE_NAME = "pyscitt"
PACKAGE_VERSION = "0.1.0"

path_here = path.abspath(path.dirname(__file__))

with open(path.join(path_here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name=PACKAGE_NAME,
    version=PACKAGE_VERSION,
    description="Tools to sign claims and interact with a SCITT CCF Ledger",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["scitt=pyscitt.cli.main:main"],
    },
    python_requires=">=3.8",
    install_requires=[
        "ccf==4.0.10",  # We temporarily bump this to 4.0.10 instead of 4.0.7 (current CCF version) so that we can upgrade cryptography to a 41.* version, which fixes several security vulnerabilities.
        "cryptography==41.*",  # needs to match ccf
        "httpx",
        "cbor2==5.4.*",
        # TODO: remove this once pycose >= 1.0.2 is released
        "pycose @ git+https://github.com/TimothyClaeys/pycose@94db358eda640966c0e0e9148110b6c66763f9e5#egg=pycose",
        "pyjwt",
        "azure-keyvault",
        "azure-identity",
    ],
    license="Apache License 2.0",
    author="SCITT CCF Team",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    url="https://github.com/microsoft/scitt-ccf-ledger/tree/main/pyscitt",
)
