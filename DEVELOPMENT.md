# Development guidelines 

The following explains how to build, run, and test scitt-ccf-ledger.

## Development environment

scitt-ccf-ledger uses a Trusted Execution Environment (TEE) to provide strong security guarantees.
This means TEE hardware, here SGX, is required to run and test scitt-ccf-ledger in full.

However, scitt-ccf-ledger also supports running in *virtual* mode which does not require TEE hardware
and is generally sufficient for local development.

### Develop within Codespaces

For *virtual* mode development only, instead of following the steps below, you can also use GitHub Codespaces and then continue with the "Building" section: 

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=562968818&machine=standardLinux32gb&devcontainer_path=.devcontainer%2Fdevcontainer.json&location=WestEurope)

### Develop within a running Docker image

Similar to Codespaces you could build and test the application within the running docker image:

```sh
docker build -t mytestimg -f .devcontainer/Dockerfile .
docker run --rm -it --env PLATFORM=virtual --volume $(pwd):/opt/app --workdir /opt/app --entrypoint /bin/bash mytestimg
# workaround to make git happy in a running docker image
/opt/app# git config --global --add safe.directory "*"

## ready to build and test now, see below commands
```

### Develop within a host machine

It is expected that you have Ubuntu 20.04. Follow the steps below to setup your development environment, replacing `<sgx|virtual>` with either one, as desired:

1. Set up your host machine: 
    - If using SGX, it is recommended that you provision a virtual machine:
      - On Azure, provision a DC-series VM, for example, [DCsv3](https://learn.microsoft.com/en-us/azure/virtual-machines/dcv3-series)
      - Enable running SGX enclaves: `sudo usermod -a -G sgx_prv $(whoami)`
    - If using virtual mode, running Ubuntu 20.04 on any platform (WSL, VM, etc.) is enough

2. Install dependencies:
    ```sh
    wget https://github.com/microsoft/CCF/archive/refs/tags/ccf-5.0.0.tar.gz
    tar xvzf ccf-5.0.0.tar.gz
    cd CCF-ccf-5.0.0/getting_started/setup_vm/
    ./run.sh app-dev.yml -e ccf_ver=5.0.0 -e platform=<sgx|virtual> -e clang_version=<11|15>
    ```

## Compiling

### Using Docker build container

When you need to quickly build it and do not have the configured development environment yet.

```sh
export PLATFORM=virtual
./docker/build.sh
```

### Using your development environment

This will expect all of the required dependencies to be set correctly.

Build scitt-ccf-ledger by running:

```sh
PLATFORM=<sgx|virtual> ./build.sh
```

## Running

### Using Docker development script

The script is used in testing, it starts the docker image and sets basic configuration. For more details refer to [docker/README.md](./docker/README.md).

```sh
export PLATFORM=virtual
./docker/run-dev.sh
```

### In your development environment

1. Build first (see above)

2. Start a single-node CCF network running the scitt-ccf-ledger application:

    ```sh
    PLATFORM=<sgx|virtual> ./start.sh
    ```

3. Before claims can be submitted, the scitt-ccf-ledger application needs to be configured. For local
   development purposes, the following command will setup the service appropriately.
   
   ```sh
   ./pyscitt.sh governance local_development --url https://127.0.0.1:8000
   ```

   Note this command should not be used for a production instance, as it will leave the service
   open to all.

## Configuring

The application expects the configuration to be submitted via the CCF proposals, for that you could use the CLI.

```sh
echo <<< EOL
{
    "policy": {
        "policy_script": "export function apply(profile, phdr) { if (!phdr.issuer) {return 'Issuer not found'}; const iss=phdr.issuer.split(':eku:'); if (iss.length !== 2 || iss[1] !== '1.3.6.1.4.1.311.10.3.13') { return 'Invalid EKU'; } }"
    },
    "authentication": {
        "allow_unauthenticated": true
    }
}
EOL >> test-config.json;

./pyscitt.sh governance propose_configuration -k --url https://localhost:8000 --member-key workspace/member0_privk.pem --member-cert workspace/member0_cert.pem --configuration test-config.json
```

Above you can see a special `workspace` directory which would have been created when running with `docker/run-dev.sh` and would contain the member keys.

### Adding x509 CA roots

Root CAs are used to validate COSE envelopes being submitted to the `/entries` endpoint. Similar to the configuration CA roots can be set with the CLI.

```sh
./pyscitt.sh governance propose_ca_certs --name x509_roots -k --url https://localhost:8000 --member-key workspace/member0_privk.pem --member-cert workspace/member0_cert.pem --ca-certs myexpectedca.pem
```

## Testing

scitt-ccf-ledger has unit tests, covering individual components of the source code, and functional tests, covering end-to-end use cases of scitt-ccf-ledger.

The unit tests can be run with:

```sh
./run_unit_tests.sh
```

All functional tests can be run with:

```sh
./run_functional_tests.sh
```

Specific functional test can also be run by passing additional `pytest` arguments, e.g. `./run_functional_tests.sh -k test_use_cacert_submit_verify_x509_signature`

Note: the functional tests will launch their own CCF network on a randomly assigned port. You do not need to start an instance beforehand.
