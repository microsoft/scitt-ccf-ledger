# Contact Ledger Service

This repository contains the source code for contract service, an application
that runs on top of [CCF](https://ccf.dev/) implementing standards developed within the [DEPA Training Framework](https://github.com/kapilvgit/depa-training/). Its purpose is to provide registry for contracts. The contract service achieves this by allowing signed contracts to be submitted to a secure immutable ledger, and returning receipts which prove contracts have been stored.

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

### Reproducing builds

See [reproducibility.md](./docs/reproducibility.md) for instructions.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).
