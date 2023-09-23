# contract-ledger

This repository contains the source code for contract-ledger, an application
that runs on top of [CCF](https://ccf.dev/) implementing standards developed within the [DEPA Training cycle](https://github.com/kapilvgit/depa-training/). Its purpose is to provide registry for contracts. contracts-ledger achieves this by allowing signed contracts to be submitted to a secure immutable ledger, and returning receipts which prove contracts have been stored and registration policies applied.

This project is at an early stage and is open sourced to facilitate academic collaborations. We are keen to engage in research collaborations on this project, please do reach out to discuss this by opening an issue.

## Getting Started

The instructions below guide you through building and deploying a local instance of contract-ledger for development and testing purposes.

Being a CCF application, contract-ledger runs in SGX enclaves. However, for testing purposes, it also supports running on non-SGX hardware in what is called *virtual* mode.

All instructions below assume Linux as the operating system.

### Using Docker

Use the following commands to start a single-node CCF network with the contract-ledger application setup for development purposes.

Note: `PLATFORM` should be set to `sgx` or `virtual` to select the type of build.

```sh
export PLATFORM=<sgx|virtual>
./docker/build.sh
./docker/run-dev.sh
```

The node is now reachable at https://127.0.0.1:8000/.

Note that `run-dev.sh` configures the network in a way that is not suitable for production, in particular it generates an ad-hoc governance member key pair and it disables API authentication.

See the `demo/contract` folder on how to interact with the application.

### Development setup

See [DEVELOPMENT.md](DEVELOPMENT.md) for instructions on building, running, and testing contract-ledger without Docker.

### Reproducing builds

See [reproducibility.md](./docs/reproducibility.md) for instructions.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).
