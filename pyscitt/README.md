CCF SCITT CLI
----------------

The CLI is extensively used in functional tests and in demo scripts:

- [Transparency service demo](../demo/cts_poc/README.md)
- [GitHub hosted DID demo](../demo/github/README.md)
- [CLI tests](../test/test_cli.py)

## Installation

CLI is written in Python and is distributed through the GitHub releases as a `wheel` file.

- Download a release: `curl -LO https://github.com/microsoft/scitt-ccf-ledger/releases/download/0.5.0/pyscitt-0.0.1-py3-none-any.whl`
- Install it: `pip install pyscitt-0.0.1-py3-none-any.whl`
- Try it: `scitt --help`

An alternative way is to clone the repository and just run [`./pyscitt.sh`](../pyscitt.sh), e.g. `./pyscitt.sh --help`
