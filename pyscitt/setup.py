# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import find_packages, setup

setup(
    name="pyscitt",
    version="0.1.0",
    description="Tools to sign claims and interact with a SCITT CCF Ledger",
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
)
