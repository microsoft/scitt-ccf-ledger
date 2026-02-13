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
    "0.12.3-0-gaaaaaaa"
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

- You could also verify the provided report with services such as Microsoft Azure Attestation Service, this step is excluded for brevity reasons

### Extract image layers from security policy

Inspect the service join policy content and extract the Rego policy used to validate the container, there might be multiple join policies but they are keyed by their digest which is in the host data measurement above:

```sh
$ cat service-join-policy.json | jq -r '.snp.hostData["5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65"]' | printf "%s" "$(cat)" > ccepolicy.rego
```

_`printf "%s" "$(cat)"` is important to not to create additional line in the file as otherwise sha256 digests will not match._

The policy is used by the Utility VM (UVM) to launch a container group (this ledger application). It contains the image layers we want to compare and be able to reproduce.

You can use an OPA agent to convert the Rego file to JSON to then select layers or do that manually, e.g.:

```sh
$ curl -s -LO https://openpolicyagent.org/downloads/v1.1.0/opa_linux_amd64_static
$ chmod 755 opa_linux_amd64_static
$ ./opa_linux_amd64_static parse ccepolicy.rego -f json > ccepolicy.json

# jq find the containers rule and extract layers of each container
$ cat ccepolicy.json | jq '[ .rules[] | select(.head.name == "containers") | .head.value.value[].value[] | select(.[].value == "layers") | .[1].value | map(.value) ]' > containerlayers.json
```

`containerlayers.json` should contain layers of all containers, our application and a `pause` container with a single layer.

**Note:** image layers in the security policy use [dmverity hashes](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html), hence you will need to convert the built container image before comparison, see [`microsoft/integrity-vhd` CLI](https://github.com/microsoft/integrity-vhd/tree/main/cmd/dmverity-vhd).

**Note:** In the example here the policy was created with the `az confcom acipolicygen` CLI for the confidential Azure container instances (C-ACI). But the policy could also be for confidential AKS (C-AKS) and the location of the containers and layers would be slightly different.

## Reproduce measurements

### 1. Verify security policy is the same

`Host data` contains the sha-256 digest of the security policy (e.g. `5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65`). The policy can be obtained like it was shown above and saved to a file `ccepolicy.rego`. The hash of the Rego policy is the same as the one in the report:

```sh
$ sha256sum ccepolicy.rego

5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65  ccepolicy.rego
```

Now it is clear that the contents of the policy (image layers) can be trusted in the next step.

### 2. Build container and compare layers

- Using the source code version that was obtained above, i.e. `"0.12.3-0-gaaaaaaa"`, clone the repository locally. The version is a long format [git describe output](https://git-scm.com/docs/git-describe):

    ```sh
    $ git clone --depth 1 --branch 0.12.3 git@github.com:microsoft/scitt-ccf-ledger.git toreproduce
    $ cd toreproduce
    ```
- Identify the expected CCF build image version and base image by inspecting the Dockerfile used for building the binary:

    ```sh
    $ cat docker/Dockerfile | grep CCF_VERSION=
    ARG CCF_VERSION=6.0.23

    $ cat docker/Dockerfile | grep BASE_IMAGE=
    ARG BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core:3.0.20250402
    ```
- Run a build inside of the CCF docker image and make sure to use a specific path (`__w/1/s`) to the sources as this is where our Azure build server copies the sources before building. If the build was done somewhere else, make sure to obtain the required path value:

    ```sh
    $ export CCF_VERSION="6.0.23"
    $ export BASE_IMAGE="mcr.microsoft.com/azurelinux/base/core:3.0.20250402"
    $ docker run -it --rm \
        -w /__w/1/s -v $(pwd):/__w/1/s \
        -v /var/run/docker.sock:/var/run/docker.sock \
        ${BASE_IMAGE} git config --global --add safe.directory "*" && PLATFORM=snp SAVE_IMAGE_PATH=image.tar ./docker/build.sh
    ```
- Convert saved image layers with dmverity cli

    ```sh
    $ curl -LO https://github.com/microsoft/integrity-vhd/releases/download/v1.4/dmverity-vhd
    $ chmod +x dmverity-vhd
    $ ./dmverity-vhd --tarball ./image.tar roothash -i ignore
    Layer 0 root hash: 3f61e43c03c18bda3c34c47a15d4025f4d4f2166e6db4c70218c39e8da8ef8da
    Layer 1 root hash: 444465dedcbb724d19ec6ffcb642ba830ea98137e26b7d39eb7fd65b1b9a5223
    Layer 2 root hash: f4132181247193a0a6c34c15ba625518dffefb639eb4017bb32450e0c6951094
    ...
    ```
- Check if the layers from `containerlayers.json` and the output above match.

### 3. Verify UVM

The details of how to reproduce the UVM (to compare it to a `measurement` in the report) are not ready yet.

UVM measurements can be authenticated using [platform endorsements](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64). To get platform endorsements:

```sh
$ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes/self > node-quote.json
$ cat node-quote.json | jq -r '.uvm_endorsements' | base64 -d > uvm_endorsements.cose
... verify cose signing envelope ...
```

UVM endorsement policy can also be seen in `service-join-policy.json`.
