# Contact Ledger Service

This repository contains the source code for contract service, an application
that runs on top of [CCF](https://ccf.dev/) implementing standards developed within the [DEPA Training Framework](https://github.com/kapilvgit/depa-training/). Its purpose is to provide registry for contracts. The contract service achieves this by allowing signed contracts to be submitted to a secure immutable ledger, and returning receipts which prove contracts have been stored.

This research project is at an early stage and is open sourced to facilitate academic collaborations. We are keen to engage in research collaborations on this project, please do reach out to discuss this by opening an issue.

## Getting Started

The instructions below guide you through building and deploying a local instance of contract service for development and testing purposes.

Being a CCF application, contract service runs in SGX enclaves. However, for testing purposes, it also supports running on non-SGX hardware in what is called *virtual* mode.

All instructions below assume Linux as the operating system.

### Sign and Register Contracts

Follow [instructions](./demo/contract/README.md) on how to sign and register contracts with an existing contract service.

### Build and Deploy using Docker

Use the following commands to start a single-node CCF network with the contract service application setup for development purposes.

Note: `PLATFORM` should be set to `sgx` or `virtual` to select the type of build.

```sh
export PLATFORM=<sgx|virtual>
./docker/build.sh
./docker/run-dev.sh
```

The node is now reachable at https://127.0.0.1:8000/.

Note that `run-dev.sh` configures the network in a way that is not suitable for production, in particular it generates an ad-hoc governance member key pair and it disables API authentication.

### Development setup

See [DEVELOPMENT.md](DEVELOPMENT.md) for instructions on building, running, and testing contract-ledger without Docker.

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

- [Transparency service demo](../demo/cts_poc/README.md)
- [GitHub hosted DID demo](../demo/github/README.md)
- [CLI tests](../test/test_cli.py)

See [pyscitt](pyscitt/README.md) for more details.

### Reproducing builds

See [reproducibility.md](./docs/reproducibility.md) for instructions.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).
