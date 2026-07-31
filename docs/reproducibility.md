# Reproducibility

The ledger application is running in a trusted execution environment and has a measurement associated with it which does not change. The goal is to reproduce the same measured value from the source code to ensure the code can be trusted, transparent and auditable.

## Prerequisites

You need a couple pieces of information to begin with:

- The ledger certificate. It might be distributed in a variety of ways by the ledger operator, please follow their guidance. Otherwise it is accessible at `https://<LEDGER-URL>/node/network`, e.g.:

    ```sh
    $ curl -k "https://<LEDGER-URL>/node/network" | jq -r .service_certificate > cacert.pem
    ```

- The quote of a running application code, get it from `https://<LEDGER-URL>/node/quotes` which will contain the measurements of each node in the network. They will be the same almost all of the time except when upgrading to the new version e.g.:

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes > node-quotes.json
    ```

- Image version, usually found in `https://<LEDGER-URL>/app/version`.

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/app/version | jq ".version"
    "0.18.2_1.0.034842-3730a2c7"
    ```
  
  Treat this value as the image version, not necessarily as an unambiguous source revision. Official image labels may identify the operator repository rather than the SCITT source repository. In this example the tag `0.18.2` points to this repository.

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
  
  - You will need host data digest to extract the correct join policy from the `service-join-policy.json` file.


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

# Preserve container names while extracting their layers.
$ jq '[ .rules[] |
    select(.head.name == "containers") |
    .head.value.value[] |
    (.value | map({key: .[0].value, value: .[1]}) | from_entries) |
    {name: .name.value, layers: [.layers.value[].value]}
  ]' ccepolicy.json > containerlayers.json
```

`containerlayers.json` should contain the names and layers of all containers, including the SCITT application, `pause` container and other operator containers, e.g. used for collecting logs. Inspect it, identify the application container name for the deployment, and select it rather than assuming it is the first entry:

```sh
$ jq . containerlayers.json
$ jq -r '.[] | select(.name == "<APPLICATION-CONTAINER-NAME>") | .layers[]' containerlayers.json > expected-layers.txt
```

The `name` field is policy-generator and deployment dependent. Older policies may omit it or use a different identifier. If it is absent, inspect the policy and select the application entry using the available identity fields or its position; verify that `expected-layers.txt` is not empty before continuing.

**Note:** image layers in the security policy use [dmverity hashes](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html), hence you will need to convert the built container image before comparison, see [`microsoft/integrity-vhd` CLI](https://github.com/microsoft/integrity-vhd/tree/main/cmd/dmverity-vhd).

**Note:** In the example here the policy was created with the `az confcom acipolicygen` CLI for the confidential Azure container instances (C-ACI). But the policy could also be for confidential AKS (C-AKS) and the location of the containers and layers would be slightly different.

## Reproduce measurements

### 1. Verify security policy is the same

`Host data` contains the sha-256 digest of the security policy (e.g. `5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65`). The policy can be obtained like it was shown above and saved to a file `ccepolicy.rego`. The hash of the Rego policy is the same as the one in the report:

```sh
$ sha256sum ccepolicy.rego

5ae7b14ee0c9c4fe267d191f25b20fffe24e29c4ac419c50501d20c869bbba65  ccepolicy.rego
```

Now it is clear that the contents of the policy (image layers) can be trusted in the next step. This is because the policy was evaluated in the UVM and it's measurement was included in the report. The report could only be generated and signed in a valid TEE.

### 2. Build container and compare layers

#### If you have access to the original image

If the original image is accessible, compute its dmverity hashes and compare them with `expected-layers.txt`. This authenticates the deployed image independently of whether a historical rebuild is possible.

Use a recent `dmverity-vhd` version that supports the OCI image layout emitted by current Docker versions. Record the exact `integrity-vhd` commit used:

```sh
$ git clone --depth 1 https://github.com/microsoft/integrity-vhd.git
$ git -C integrity-vhd checkout a63cb455d8cab7a3441d1c0cb10dac4d658e20ce
$ git -C integrity-vhd rev-parse HEAD
$ go build -C integrity-vhd -o ../dmverity-vhd ./cmd/dmverity-vhd
$ docker pull <ORIGINAL-IMAGE>
$ ./dmverity-vhd --docker roothash -i <ORIGINAL-IMAGE> > original-roothash.json
$ jq -r '.layers[]' original-roothash.json > original-layers.txt
$ diff -u expected-layers.txt original-layers.txt
```

#### Rebuild the image from source

To rebuild, check out the resolved SCITT version using the application version tag:

```sh
$ git clone https://github.com/microsoft/scitt-ccf-ledger.git source
$ git -C source checkout <TAG or COMMIT>
```

Reproduce the command used in the build. A representative command is:

```sh
$ export IMAGE_TAG="<APP-VERSION>"
$ export IMAGE="scitt-reproduction:${IMAGE_TAG}"
$ export ARTIFACTS="$(pwd)/artifacts"
$ export SOURCE_DATE_EPOCH="$(git -C source show -s --format=%ct HEAD)"
$ mkdir -p "${ARTIFACTS}"
$ (cd source && tar --exclude=env -cf - .) | tar -xf - -C "${ARTIFACTS}"

$ DOCKER_BUILDKIT=1 docker build \
    --pull \
    --no-cache \
    --force-rm \
    -f "${ARTIFACTS}/docker/Dockerfile" \
    --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    --build-arg SCITT_VERSION_OVERRIDE="${IMAGE_TAG}" \
    -t "${IMAGE}" \
    "${ARTIFACTS}"
```

Compute and compare the rebuilt hashes:

```sh
$ ./dmverity-vhd --docker roothash -i "${IMAGE}" > rebuilt-roothash.json
$ jq -r '.layers[]' rebuilt-roothash.json > rebuilt-layers.txt
$ diff -u expected-layers.txt rebuilt-layers.txt
```

Docker labels affect the image configuration and full image digest, but not the filesystem dmverity layer hashes. Include the labels from the build log when reproducing the complete image digest.

#### Historical build limitations

Some historical images cannot be reproduced bit-for-bit from the source revision and Docker command alone as the environment changed over time introducing values that change on each build. To mitigate against these issues, an automated reproducibility check is run on every commit.

The GitHub Actions check builds the same normalized source context twice on independent runners and requires the complete image IDs to match. The OneBranch pipeline creates the same normalized context and a canonical local reference build before running `onebranch.pipeline.imagebuildinfo`. It requires the ordered filesystem layer digests of the reference and published images to match exactly. Their complete image IDs are expected to differ because the governed OneBranch task adds pipeline traceability labels to the image configuration; those labels do not alter filesystem or dmverity layer hashes.

### 3. Verify UVM

The details of how to reproduce the UVM (to compare it to a `measurement` in the report) are not ready yet.

UVM measurements can be authenticated using [platform endorsements](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64). To get platform endorsements:

```sh
$ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes/self > node-quote.json
$ cat node-quote.json | jq -r '.uvm_endorsements' | base64 -d > uvm_endorsements.cose
... verify cose signing envelope ...
```

UVM endorsement policy can also be seen in `service-join-policy.json`.

