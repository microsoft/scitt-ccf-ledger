# Reproducibility

The ledger application is running in a trusted execution environment and has a measurement associated with it which does not change. The goal is to reproduce the same measured value from the source code to ensure the code can be trusted, transparent and auditable.

The assumption here is that the original build was done using a Docker.

## Prerequisites

You need a couple pieces of information to begin with:

- The ledger certificate. It might be distributed in a variety of ways by the ledger operator, please follow their guidance. Otherwise it is accessible at `https://<LEDGER-URL>/app/parameters`, e.g.:

    ```sh
    $ curl -k "https://<LEDGER-URL>/app/parameters" | jq -r .serviceCertificate | base64 -d > cacert.der
    $ openssl x509 -inform der -in cacert.der > cacert.pem
    ```

- The quote of a running application code, get it from `https://<LEDGER-URL>/node/quotes` which will contain the measurements of each node in the network. They will be the same almost all of the time except when upgrading to the new version e.g.:

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes > node-quotes.json
    ```

- Source code version which was used to build the application, usually found in `https://<LEDGER-URL>/app/version`. If `app/version` is ambiguous then check the build logs of the Docker image to understand which commit produced the candidate value. e.g., `fb2c496416fbab20837fedda0ba6db58d819fa5f5c1b3916062eb2fb9d889966` was built from `fd77c0c69ee890bdc2fcf6ef0c9dddb7b211e164`.

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/app/version | jq ".version"
    "0.11.0"
    ```

- Security policy used to verify the container image ([ccf docs](https://microsoft.github.io/CCF/main/governance/gov_api_schemas/2024-07-01.html#get--gov-service-join-policy)), it will contain image layers, e.g.:

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/gov/service/join-policy?api-version=2024-07-01 > service-join-policy.json
    ```

### Extract measurements from the report

The quote contains the attestation report that has the necessary measurements. `Measurement` will have the launch measurement of the guest virtual machine (aka utility VM or UVM) which was used to run the container. `Host data` will have the security policy measurement which was used to make sure no other container was launched except the one you are inspecting. More detail on implementing relying party logic can be [found in Confidential ACI scheme documentation](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64).

- Decode the report and save it to a file:

    ```sh
    $ cat node-quotes.json | jq -r '.quotes[0].raw' | base64 -d > snp-report.bin
    ```

- Inspect the report to get the measurements. You could use https://github.com/virtee/snpguest to display the report details, e.g.:

    ```sh
    $ curl -LO https://github.com/virtee/snpguest/archive/refs/tags/v0.8.0.tar.gz
    $ tar -xvf v0.8.0.tar.gz
    $ cd snpguest-0.8.0
    $ cargo build -r
    $ cd ..
    $ ./snpguest-0.8.0/target/release/snpguest display report snp-report.bin
    <...>
    Measurement:
    18 25 a4 bf 2a 9c 38 35 66 a7 17 63 26 83 9a c0
    e3 6a 1c 5b 37 e9 e6 fa bc 8f dd 71 30 d5 8c ef
    56 f4 34 75 02 b9 47 89 53 0c ec 19 8a a5 15 43

    Host Data:
    5a e7 b1 4e e0 c9 c4 fe 26 7d 19 1f 25 b2 0f ff
    e2 4e 29 c4 ac 41 9c 50 50 1d 20 c8 69 bb ba 65
    <...>
    ```

- You could also verify the provided report with services such as Microsoft Azure Attestation Service, this step is excluded for the brevity reasons

### Extract image layers from security policy

Inspect the service join policy content anextract the Rego policy used to validate the container:

```sh
$ cat service-join-policy.json | jq -r '.snp.hostData["5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65"]' | printf "%s" "$(cat)" > ccepolicy.rego
```

`printf "%s" "$(cat)"` is important to not to create additional line in the file as otherwise sha256 digests will not match.

The policy is used by the Utility VM (UVM) to launch a container group (this application). It contains the image layers we want to compare and be able to reproduce.

We can use an OPA agent to convert the Rego file to JSON to then select layers or do that manually:

```sh
$ curl -s -LO https://openpolicyagent.org/downloads/v1.1.0/opa_linux_amd64_static
$ chmod 755 opa_linux_amd64_static
$ ./opa_linux_amd64_static parse ccepolicy.rego -f json > ccepolicy.json

# jq find the containers rule and extract layers of each container
$ cat ccepolicy.json | jq '[ .rules[] | select(.head.name == "containers") | .head.value.value[].value[] | select(.[].value == "layers") | .[1].value | map(.value) ]' > containerlayers.json
```

`containerlayers.json` should contain layers of all containers, our application and a `pause` container with a single layer.

## Reproduce measurements

### Verify security policy is the same

`Host data` contains the hash of the security policy (e.g. `5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65`). The policy can be obtained like it was shows above and saved to a file `ccepolicy.rego`. The hash of the Rego policy is the same as the one in the report:

```sh
$ sha256sum ccepolicy.rego

5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65  ccepolicy.rego
```

### Build container and compare layers

- Using the source code version that was obtained above, i.e. `"0.11.0"`, clone the repository locally

    ```sh
    $ git clone --depth 1 --branch 0.11.0 git@github.com:microsoft/scitt-ccf-ledger.git toreproduce
    $ cd toreproduce
    ```
- Identify the expected CCF build image version by inspecting the Dockerfile used for building the binary:

    ```sh
    $ cat docker/snp.Dockerfile | grep CCF_VERSION=
    ARG CCF_VERSION=6.0.0-dev8
    ```
- Run a build inside of the CCF docker image and make sure to use a specific path (__w/1/s) to the sources as this is where our Azure build server copies the sources before building. If the build was done somewhere else, make sure to obtain the required path value:

    ```sh
    $ export CCF_VERSION="6.0.0-dev8"
    $ docker run -it --rm \
        -w /__w/1/s -v $(pwd):/__w/1/s \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --env PLATFORM=snp \
        ghcr.io/microsoft/ccf/app/dev/virtual:ccf-${CCF_VERSION} git config --global --add safe.directory "*" && ./docker/build.sh
    ```

### Guest VM

The details of how to reproduce the Guest VM (to compare it to a `measurement` in the report) are not ready yet.

Guest VM measurements can be authenticated using [platform endorsements](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64). To get platform endorsements:

```sh
$ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes/self > node-quote.json
$ cat node-quote.json | jq -r '.uvm_endorsements' | base64 -d > uvm_endorsements.cose
```

UVM endoresement policy can also be seen in `service-join-policy.json`.
