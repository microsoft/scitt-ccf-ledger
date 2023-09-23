# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import find_packages, setup

setup(
    name="pyscitt",
    version="0.0.1",
    description="Tools to sign claims and interact with a SCITT CCF Ledger",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    entry_points={
        "console_scripts": ["scitt=pyscitt.cli.main:main"],
    },
    python_requires=">=3.8",
    install_requires=[
        "ccf==3.0.12",
        "cryptography==39.*",  # needs to match ccf
        "httpx",
        "cbor2",
        # TODO: remove this once pycose >= 1.0.2 is released
        "pycose @ git+https://github.com/kapilvgit/pycose@87169e69d39a7623b01272644c01773d90e74731#egg=pycose",
        "pyjwt",
        "azure-keyvault",
        "azure-identity",
    ],
)
