# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from os import path

from setuptools import find_packages, setup

PACKAGE_NAME = "pyscitt"
PACKAGE_VERSION = "0.7.1"

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
        "ccf==6.0.0-dev10",
        "cryptography==44.*",  # needs to match ccf
        "httpx",
        "cbor2==5.4.*",
        "pycose==1.1.0",
        "pyjwt",
        "azure-keyvault",
        "azure-identity",
    ],
    license="Apache License 2.0",
    author="SCITT CCF Team",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Science/Research",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    url="https://github.com/microsoft/scitt-ccf-ledger/tree/main/pyscitt",
)
