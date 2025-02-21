# Development guidelines 

The following explains how to build, run, and test scitt-ccf-ledger.

## Development environment

scitt-ccf-ledger uses a Trusted Execution Environment (TEE) to provide strong security guarantees.
This means TEE hardware (AMD SEV-SNP) is required to run and test scitt-ccf-ledger in full.

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

It is expected that you have Ubuntu 20.04. Follow the steps below to setup your development environment, replacing `<virtual|snp>` with either one, as desired:

1. Set up your host machine:
    - If using virtual mode, running Ubuntu 20.04 on any platform (WSL, VM, etc.) is enough
    - If using SNP, you should use a machine with SNP hardware support and a platform that allows to enforce security policies for containers running on it (e.g., [Confidential Containers on AKS](https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview), [Confidential Containers on ACI](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview))

2. Install dependencies:
    ```sh
    wget https://github.com/microsoft/CCF/archive/refs/tags/ccf-6.0.0-dev19.tar.gz
    tar xvzf ccf-6.0.0-dev19.tar.gz
    cd CCF-ccf-6.0.0-dev19/getting_started/setup_vm/
    ./run.sh app-dev.yml -e ccf_ver=6.0.0-dev19 -e platform=<virtual|snp> -e clang_version=15
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
PLATFORM=<virtual|snp> ./build.sh
```

## Running

### Using Docker development script

The script is used in testing, it starts the docker image and sets basic [configuration](docs/configuration.md). For more details refer to [docker/README.md](./docker/README.md).

```sh
export PLATFORM=virtual
./docker/run-dev.sh
```

### In your development environment

1. Build first (see above)

2. Start a single-node CCF network running the scitt-ccf-ledger application:

    ```sh
    PLATFORM=<virtual|snp> ./start.sh
    ```

3. Before claims can be submitted, the scitt-ccf-ledger application needs to be configured. For local
   development purposes, the following command will setup the service appropriately.
   
   ```sh
   ./pyscitt.sh governance local_development --url https://127.0.0.1:8000
   ```

   Note this command should not be used for a production instance, as it will leave the service
   open to all.

## Configuring

The application expects the [configuration](docs/configuration.md) to be submitted via the CCF proposals, for that you could use the CLI.

```sh
echo <<< EOL
{
    "policy": {
        "policyScript": "export function apply(phdr) { if (!phdr.issuer) {return 'Issuer not found'} if (phdr.issuer !== 'did:x509:0:sha256:HnwZ4lezuxq/GVcl/Sk7YWW170qAD0DZBLXilXet0jg=::eku:1.3.6.1.4.1.311.10.3.13') { return 'Invalid issuer'; } }"
    },
    "authentication": {
        "allowUnauthenticated": true
    }
}
EOL >> test-config.json;

./pyscitt.sh governance propose_configuration -k --url https://localhost:8000 --member-key workspace/member0_privk.pem --member-cert workspace/member0_cert.pem --configuration test-config.json
```

Above you can see a special `workspace` directory which would have been created when running with `docker/run-dev.sh` and would contain the member keys.

### Adding x509 CA roots

Root CAs are used to validate COSE envelopes being submitted to the `/entries` endpoint. Similar to the [configuration](docs/configuration.md) CA roots can be set with the CLI.

```sh
./pyscitt.sh governance propose_ca_certs --name x509_roots -k --url https://localhost:8000 --member-key workspace/member0_privk.pem --member-cert workspace/member0_cert.pem --ca-certs myexpectedca.pem
```

## Testing

scitt-ccf-ledger has unit tests, covering individual components of the source code, and functional tests, covering end-to-end use cases of scitt-ccf-ledger.

### Unit tests

The unit tests can be run with `run_unit_tests.sh` script.

**Using your host environment**

```sh
PLATFORM=virtual CMAKE_BUILD_TYPE=Debug ./build.sh
./run_unit_tests.sh
```

### Functional (e2e) tests

To start the tests you need to use the script `run_functional_tests.sh`.

Specific functional test can also be run by passing additional `pytest` arguments, e.g. `./run_functional_tests.sh -k test_use_cacert_submit_verify_x509_signature`

Note: the functional tests will launch their own CCF network on a randomly assigned port. You do not need to start an instance beforehand.

**Using Docker**

The script will launch the built Docker image and will execute tests against it:

```sh
PLATFORM="virtual" ./docker/build.sh
DOCKER=1 PLATFORM=virtual ./run_functional_tests.sh
```

**Using your host environment**

```sh
PLATFORM=virtual ./build.sh
PLATFORM=virtual ./run_functional_tests.sh
```

### Address sanitization

To enable ASan it is necessary to build CCF from source:

```sh
PLATFORM=virtual CMAKE_BUILD_TYPE=Debug BUILD_CCF_FROM_SOURCE=ON ./build.sh
# once complete you run the tests
./run_unit_tests.sh
PLATFORM=virtual ./run_functional_tests.sh
```

### Fuzzing

Run HTTP API fuzzing tests after building the application:

**Using Docker**

```sh
DOCKER=1 ./run_fuzz_tests.sh
```

**Using your host environment**

```sh
./run_fuzz_tests.sh
```

## AMD SEV-SNP platform

To use [AMD SEV-SNP](https://microsoft.github.io/CCF/main/operations/platforms/snp.html) as a platform, it is required to pass additional configuration values required by CCF for the attestation on AMD SEV-SNP hardware. These values may differ depending on which SNP platform you are using (e.g., Confidential Containers on ACI, Confidential Containers on AKS).

The required configs can be set using the `SNP_ATTESTATION_CONFIG` environment variable in any of the development and test scripts. The variable should be set to the path of a JSON file containing the [CCF SNP attestation configuration](https://microsoft.github.io/CCF/main/operations/configuration.html#attestation). An example file would look like this:

```json
{
    "snp_endorsements_servers": [
      {
        "type": "AMD",
        "url": "kdsintf.amd.com"
      }
    ],
    "snp_security_policy_file": "/path/to/security-policy-base64",
    "snp_uvm_endorsements_file": "/path/to/reference-info-base64"
}
```

Please refer to [the CCF documentation on the AMD SEV-SNP platform](https://microsoft.github.io/CCF/main/operations/platforms/snp.html) for more details on how to set these values in each platform.

To start SCITT on SNP, you would run:

```sh
PLATFORM=snp SNP_ATTESTATION_CONFIG=/path/to/snp-attestation-config.json ./start.sh
```

To run the SCITT functional tests on SNP, you would run:

```sh
PLATFORM=snp SNP_ATTESTATION_CONFIG=/path/to/snp-attestation-config.json ./run_functional_tests.sh
```
