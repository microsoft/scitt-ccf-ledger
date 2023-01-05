# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import find_packages, setup

setup(
    name="pyscitt",
    version="0.0.1",
    description="Tools to sign claims and interact with a SCITT CCF Ledger",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["scitt=pyscitt.cli.main:main"],
    },
    python_requires=">=3.8",
    install_requires=[
        "ccf==3.0.2",
        "cryptography==38.*",  # needs to match ccf
        "httpx",
        "cbor2",
        "pycose>=1.0.1",
        "pyjwt",
        "azure-keyvault",
        "azure-identity",
        "pyasn1",
    ],
)
