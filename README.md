# scitt-ccf-ledger

[![Build and test](https://github.com/microsoft/scitt-ccf-ledger/actions/workflows/build-test.yml/badge.svg)](https://github.com/microsoft/scitt-ccf-ledger/actions/workflows/build-test.yml) [![Build Status](https://github-private.visualstudio.com/microsoft/_apis/build/status%2FOneBranch%2Fscitt-ccf-ledger-wrapper%2Fscitt-ccf-ledger-wrapper-Official?repoName=scitt-ccf-ledger-wrapper&branchName=master)](https://github-private.visualstudio.com/microsoft/_build/latest?definitionId=716&repoName=scitt-ccf-ledger-wrapper&branchName=master)

This repository contains the source code for scitt-ccf-ledger, an application
that runs on top of [CCF](https://github.com/microsoft/CCF) implementing draft standards developed within the [IETF SCITT WG](https://datatracker.ietf.org/wg/scitt/about/). Its purpose is to provide provenance for artefacts in digital supply chains, increasing trust in those artefacts. scitt-ccf-ledger achieves this by allowing signed claims about artefacts to be submitted to a secure immutable ledger, and returning receipts which prove claims have been stored and registration policies applied.

This research project is at an early stage and is open sourced to facilitate academic collaborations. We are keen to engage in research collaborations on this project, please do reach out to discuss this by opening an issue.

## Getting Started

The instructions below guide you through building and deploying a local instance of scitt-ccf-ledger for development and testing purposes.

Being a CCF application, scitt-ccf-ledger targets AMD SEV-SNP but also supports running on x86-64 hardware without TEE support in what is called *virtual* mode.

All instructions below assume Linux as the operating system.

### Using Docker

Use the following commands to start a single-node CCF network with the scitt-ccf-ledger application setup for development purposes.

> Note: `PLATFORM` should be set to `virtual`, or `snp` to select the type of build.
> Note: if `PLATFORM` is set to `snp`, additional configuration is required. Refer to [this section](DEVELOPMENT.md#amd-sev-snp-platform) for more details.

```sh
export PLATFORM=<virtual|snp>
./docker/build.sh
./docker/run-dev.sh
```

The node is now reachable at https://127.0.0.1:8000/.

Note that `run-dev.sh` configures the network in a way that is not suitable for production, in particular it generates an ad-hoc governance member key pair and it disables API authentication.

See the `demo/` folder on how to interact with the application.

### Development setup

See [DEVELOPMENT.md](DEVELOPMENT.md) for instructions on building, running, and testing scitt-ccf-ledger.

### Using the CLI

To help with the configuration of an application or to be able to interact with its API you could leverage the available CLI.

The `pyscitt` CLI is written in Python and is available on PyPi [here](https://pypi.org/project/pyscitt/). To install it, you can use the following command:

```sh
pip install pyscitt
```

The CLI is also distributed through the GitHub releases as a `wheel` file. Optionally, it can be used from within the repository using the [`./pyscitt.sh`](../pyscitt.sh) script. For example: 

```sh
./pyscitt.sh --help
```

The CLI is extensively used in the following functional tests and demo scripts:

- [Transparency service demo](./demo/cts_poc/README.md)
- [GitHub hosted DID demo](./demo/github/README.md)
- [CLI tests](./test/test_cli.py)

See [pyscitt](pyscitt/README.md) for more details.

### Reproducing builds

See [reproducibility.md](./docs/reproducibility.md) for instructions.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

### Trademarks 
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
