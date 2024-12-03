# Reproducibility

The ledger application is running in a trusted execution environment and has a measurement associated with it which does not change. The goal is to reproduce the same measured value from the source code to ensure the code can be trusted, transparent and auditable.

The assumption here is that the original build was done using a Docker.

## Prerequisites

You need a couple pieces of information to begin with:

- The ledger certificate. It might be distributed in a variety of ways by the ledger operator, please follow their guidance. Otherwise it is accessible at `https://<LEDGER-URL>/app/parameters`.

- The quote of a running application code, get it from `https://<LEDGER-URL>/node/quotes/self` (replace <LEDGER-URL> with the URL of your ledger), e.g.:

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes/self > node-quote.json
    ```
- Source code version which was used to build the application, usually found in `https://<LEDGER-URL>/app/version`. If `app/version` is ambiguous then check the build logs of the Docker image to understand which commit produced the candidate value. e.g., `fb2c496416fbab20837fedda0ba6db58d819fa5f5c1b3916062eb2fb9d889966` was built from `fd77c0c69ee890bdc2fcf6ef0c9dddb7b211e164`.

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/app/version | jq ".scitt_version"
    "1.2.3"
    ```

### Extract measurements

The quote contains the attestation report that has the necessary measurements. `Measurement` will have the launch measurement of the guest virtual machine (aka utility VM or UVM) which was used to run the container. `Host data` will have the security policy measurement which was used to make sure no other container was launched except the one you are inspecting, it will contain container image layer hashes.

- Decode the report and save it to a file:

    ```sh
    cat node-quote.json | jq -r '.raw' | base64 -d > snp-report.bin
    ```

- Inspect the report to get the measurements. You could use https://github.com/virtee/snpguest to display the report details:

    ```sh
    snpguest display report snp-report.bin
    ```

## Reproduce measurements

### Guest VM

The details of how to reproduce the Guest VM are not ready yet. The source code will be open sourced at some point and it will be possible to build from it to reproduce the `measurement` in the report. It will make sure that the security policy enforcement logic is as expected.

### Security policy and container image

`Host data` contains the hash of the security policy, but we do not have the steps to obtain the policy yet.
