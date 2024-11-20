# Reproducibility

The ledger application is running in an Intel SGX enclave and has a measurement (`MRENCLAVE` value) associated with it which does not change. The goal is to reproduce the same measured value from the source code to ensure the code can be trusted, transparent and auditable.

The assumption here is that the original build was done using a Docker.

## Prerequisites

You need a couple pieces of information to begin with:

- The ledger certificate. It might be distributed in a variety of ways by the ledger operator, please follow their guidance. Otherwise it is accessible at `https://<LEDGER-URL>/app/parameters`.

- The measurement of a running application code, get it from `https://<LEDGER-URL>/node/quotes/self` (replace <LEDGER-URL> with the URL of your ledger), e.g.:

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes/self | jq .mrenclave
    "96c40e2532ba329849e7fede3f3d888a0423a1dc0f3d0511b138617cc3aa9e94"
    ```
- Source code version which was used to build the application, usually found in `https://<LEDGER-URL>/app/version`. If `app/version` is ambiguous then check the build logs of the SGX Docker image to understand which commit produced the candidate value. e.g., `fb2c496416fbab20837fedda0ba6db58d819fa5f5c1b3916062eb2fb9d889966` was built from `fd77c0c69ee890bdc2fcf6ef0c9dddb7b211e164`.

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/app/version | jq ".scitt_version"
    "0.7.2"
    ```

## Reproduce measurement

To reproduce the same measurement do a docker build locally using the expected build image from [`microsoft/CCF`](https://github.com/microsoft/ccf):

- Clone the repository and check out the tag or commit id that built the binary:

    ```
    $ git clone ...
    ...
    $ git checkout 0.7.2
    ```

- Identify the expected CCF build image version by inspecting the [Dockerfile](docker/enclave.Dockerfile) used for building the binary:

    ```
    $ cat docker/enclave.Dockerfile | grep CCF_VERSION=
    ARG CCF_VERSION=5.0.10
    ```

- Run a build inside of the CCF docker image and make sure to use a specific path (`__w/1/s`) to the sources as this is where our Azure build server copies the sources before building. If the build was done somewhere else, make sure to obtain the required path value:

    ```sh
    $ export CCF_VERSION="5.0.10"
    $ docker run -it --rm \
        -w /__w/1/s -v $(pwd):/__w/1/s \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --env PLATFORM=sgx \
        FROM ghcr.io/microsoft/ccf/app/dev/sgx:ccf-"$CCF_VERSION" git config --global --add safe.directory "*" && ./docker/build.sh
    ```
- The build will print the value of `MRENCLAVE` in the output, similar to:

    ```sh
    mrenclave.txt
    96c40e2532ba329849e7fede3f3d888a0423a1dc0f3d0511b138617cc3aa9e94
    ```

- As you can see in the example, the value printed in the build output matched the one from a running application.