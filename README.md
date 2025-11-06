# scitt-ccf-ledger

[![Build and test](https://github.com/microsoft/scitt-ccf-ledger/actions/workflows/build-test.yml/badge.svg)](https://github.com/microsoft/scitt-ccf-ledger/actions/workflows/build-test.yml) [![Build Status](https://github-private.visualstudio.com/microsoft/_apis/build/status%2FOneBranch%2Fscitt-ccf-ledger-wrapper%2Fscitt-ccf-ledger-wrapper-Official?repoName=scitt-ccf-ledger-wrapper&branchName=master)](https://github-private.visualstudio.com/microsoft/_build/latest?definitionId=716&repoName=scitt-ccf-ledger-wrapper&branchName=master)

This repository contains the source code for scitt-ccf-ledger, an application
that runs on top of [CCF](https://github.com/microsoft/CCF) implementing draft standards developed within the IETF. See [SCITT Standard alignment](docs/scitt.md).

The purpose of scitt-ccf-ledger is to provide transparent provenance for artefacts in digital supply chains. It achieves this by allowing signed claims about artefacts to be submitted to a secure immutable ledger, and returning receipts which prove claims have been stored and registration policies applied.

This project is open source to facilitate auditability and academic collaboration. We are keen to engage in research collaboration on this project, please do reach out to discuss this by opening an issue.

## Quick start

The instructions below guide you through building and deploying a local instance of scitt-ccf-ledger for development and testing purposes.

Being a CCF application, scitt-ccf-ledger targets AMD SEV-SNP but also supports running on x86-64 hardware without TEE support in what is called *virtual* mode.

All instructions below assume Linux as the operating system and the availability of docker and python.

> Note that `run-dev.sh` configures the network in a way that is not suitable for production, in particular it generates an ad-hoc governance member key pair, disables API authentication and sets permissive policy.

First, start the service in one terminal window:

```sh
export PLATFORM=virtual
./docker/build.sh
./docker/run-dev.sh

# Output would show:
# ...
# 2025-11-06T13:10:51.559932Z        100 [info ] CCF/src/host/socket.h:49             | TCP RPC Client listening on 0.0.0.0:8000
# ...
# 2025-11-06T13:11:01.743871Z -0.012 0   [info ] CCF/src/node/rpc/frontend.h:949      | Opening frontend
# 2025-11-06T13:11:01.743882Z -0.012 0   [info ] CCF/src/node/node_state.h:2581       | Service open at seqno 9
# ...
```

Then, in **another terminal** window you can submit a test signed statement and get transparent statement:

```sh
# use the python virtual environment which was setup in the previous step
source venv/bin/activate
# use CLI to submit test payload
scitt submit test/payloads/manifest.spdx.json.sha384.digest.cose --development --url "https://localhost:8000" --transparent-statement output.cose

# 2025-11-06 13:19:16.006 | DEBUG    | pyscitt.client:request:402 - POST /entries 202
# 2025-11-06 13:19:16.009 | DEBUG    | pyscitt.client:request:402 - GET /operations/2.13 202
# 2025-11-06 13:19:18.012 | DEBUG    | pyscitt.client:request:402 - GET /operations/2.13 (attempt #2) 200
# 2025-11-06 13:19:18.015 | DEBUG    | pyscitt.client:request:402 - GET /entries/2.13/statement 503 TransactionNotCached
# 2025-11-06 13:19:19.017 | DEBUG    | pyscitt.client:request:402 - GET /entries/2.13/statement (attempt #2) 200
# Registered test/payloads/manifest.spdx.json.sha384.digest.cose as transaction 2.13
# Received output.cose
```

## Supported inputs

See [inputs.md](./docs/inputs.md) to understand what can you register and store in the service.

## Usage examples

See [demo/](demo/) directory containing steps to launch and use the service.

## Development and testing

See [DEVELOPMENT.md](DEVELOPMENT.md) for instructions on building, running, and testing scitt-ccf-ledger.

## Available clients

See [clients.md](./docs/clients.md) to get a list of available clients to use to interact with the service.

## Configuration

See [configuration.md](./docs/configuration.md) for instructions on how to configure registration policies and authentication.

## Reproducing builds

See [reproducibility.md](./docs/reproducibility.md) for instructions.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

### Trademarks 

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
