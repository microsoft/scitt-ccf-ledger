# Development guidelines 

The following explains how to build, run, and test scitt-ccf-ledger outside of Docker.

## Development environment

[![Open in GitHub Codespaces (virtual mode)](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=590635544)

scitt-ccf-ledger uses a Trusted Execution Environment (TEE) to provide strong security guarantees.
This means TEE hardware, here SGX, is required to run and test scitt-ccf-ledger in full.

However, scitt-ccf-ledger also supports running in *virtual* mode which does not require TEE hardware
and is generally sufficient for local development.

Follow the steps below to setup your development environment, replacing `<sgx|virtual>` with either one, as desired:

1. Set up machine: 
    - If using SGX, it is recommended that you provision a virtual machine:
      - On Azure, provision a DC-series VM, for example, [DCsv2](https://learn.microsoft.com/en-us/azure/virtual-machines/dcv2-series)
      - Enable running SGX enclaves: `sudo usermod -a -G sgx_prv $(whoami)`
    - If using virtual mode, running Ubuntu 20.04 on any platform (WSL, VM, etc.) is enough

2. Install dependencies:
    ```sh
    wget https://github.com/microsoft/CCF/archive/refs/tags/ccf-3.0.2.tar.gz
    tar xvzf ccf-3.0.2.tar.gz
    cd CCF-ccf-3.0.2/getting_started/setup_vm/
    ./run.sh app-dev.yml -e ccf_ver=3.0.2 -e platform=<sgx|virtual>
    ```

## Building

1. Clone the repository and change into the scitt-ccf-ledger folder:
    ```sh
    git clone https://github.com/microsoft/scitt-ccf-ledger
    cd scitt-ccf-ledger
    ```

2. Build scitt-ccf-ledger by running:
    ```sh
    PLATFORM=<sgx|virtual> ./build.sh
    ```

## Running

1. Start a single-node CCF network running the scitt-ccf-ledger application:
    ```sh
    PLATFORM=<sgx|virtual> ./start.sh
    ```

2. Before claims can be submitted, the scitt-ccf-ledger application needs to be configured. For local
   development purposes, the following command will setup the service appropriately.
   ```sh
   ./pyscitt.sh governance local_development --url https://127.0.0.1:8000
   ```

   Note this command should not be used for a production instance, as it will leave the service
   open to all.

## Testing

scitt-ccf-ledger has unit tests, covering individual components of the source code, and functional tests, covering end-to-end use cases of scitt-ccf-ledger.

The unit tests can be run with:

```sh
./run_unit_tests.sh
```

The functional tests can be run with:

```sh
./run_functional_tests.sh
```

Note: the functional tests will launch their own CCF network on a randomly assigned port. You do not need to start an instance beforehand.
