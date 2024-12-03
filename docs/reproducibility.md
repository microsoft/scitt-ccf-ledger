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

The quote contains the attestation report that has the measurements. `Measurement` will have the launch measurement of the guest virtual machine (aka utility VM or UVM) which was used to run the container. `Host data` will have the security policy measurement.

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

Guest VM measurements can be authenticated using [platform endorsements](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64). To get platform endorsements:

```sh
cat node-quote.json | jq -r '.uvm_endorsements' | base64 -d > uvm_endorsements.cose
```

The details of how to reproduce the Guest VM (to compare it to a `measurement` in the report) are not ready yet.

### Security policy and container image

`Host data` contains the hash of the security policy, but we do not have the steps to obtain the policy yet. Container image would be linked to the policy.
