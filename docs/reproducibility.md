# Reproducibility

The ledger application is running in a trusted execution environment and has a measurement associated with it which does not change. The goal is to reproduce the same measured value from the source code to ensure the code can be trusted, transparent and auditable.

There are two related checks:

1. Authenticate the deployed image layers against the ledger security policy.
2. Rebuild the image from source and compare the rebuilt layers with the authenticated layers.

The first check can be performed for any accessible historical image. The second check requires all build inputs to be deterministic or preserved. A source commit and Dockerfile alone are not sufficient when generated files contain timestamps, database state, or order that depends on the build host.

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
    "0.12.3-0-gaaaaaaa"
    ```

  Treat this value as the image version, not necessarily as an unambiguous source revision. Official image labels may identify the wrapper pipeline repository rather than the SCITT source repository. Obtain the resolved SCITT commit from the pipeline checkout or build record.

- Security policy used to verify the container image ([ccf docs](https://microsoft.github.io/CCF/main/governance/gov_api_schemas/2024-07-01.html#get--gov-service-join-policy)), it will contain image layers, e.g.:

    ```sh
    $ curl -s --cacert cacert.pem https://<LEDGER-URL>/gov/service/join-policy?api-version=2024-07-01 > service-join-policy.json
    ```

- The original build record. Preserve or obtain:

  - the resolved SCITT source commit and image tag;
  - the complete Docker command and build context;
  - the Docker Engine and BuildKit versions;
  - the base image reference and digest;
  - source file modes and modification times, or the build's `SOURCE_DATE_EPOCH`;
  - the original image digest and, when available, the saved image tarball.

  These values should be published as release artifacts for future builds.

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

# Preserve container names while extracting their layers.
$ jq '[ .rules[] |
    select(.head.name == "containers") |
    .head.value.value[] |
    (.value | map({key: .[0].value, value: .[1]}) | from_entries) |
    {name: .name.value, layers: [.layers.value[].value]}
  ]' ccepolicy.json > containerlayers.json
```

`containerlayers.json` should contain the names and layers of all containers, including the SCITT application and a `pause` container. Inspect it, identify the application container name for the deployment, and select it rather than assuming it is the first entry:

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

Now it is clear that the contents of the policy (image layers) can be trusted in the next step.

### 2. Build container and compare layers

First, if the original image is accessible, compute its dmverity hashes and compare them with `expected-layers.txt`. This authenticates the deployed image independently of whether a historical rebuild is possible.

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

Older `dmverity-vhd` releases may report missing hashes when reading a modern OCI-formatted `docker save` tarball. Prefer `--docker` with a compatible version, or use a tarball only after confirming that the tool supports its layout.

To rebuild, check out the resolved SCITT commit from the build record:

```sh
$ git clone https://github.com/microsoft/scitt-ccf-ledger.git source
$ git -C source checkout <SCITT-COMMIT>
```

Official OneBranch builds copy the checked-out sources into an `artifacts` build context and invoke the Docker task with BuildKit, cache disabled, and a version override. Reproduce the command recorded in the build log. A representative command is:

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

The absolute build-context path, such as `/mnt/vss/_work/docker/artifacts`, is normally not stored in layers copied by this Dockerfile. The context's contents, modes, modification times, ignore rules, and relative paths do affect the result. Mounting the context at the path from the log is useful for faithfully replaying the command, but does not replace preserving its metadata.

Do not use `docker/build.sh` to reproduce an official image unless the build log shows that it was used. That script derives the version with `git describe` and does not include all flags or labels added by the official Docker task.

Compute and compare the rebuilt hashes:

```sh
$ ./dmverity-vhd --docker roothash -i "${IMAGE}" > rebuilt-roothash.json
$ jq -r '.layers[]' rebuilt-roothash.json > rebuilt-layers.txt
$ diff -u expected-layers.txt rebuilt-layers.txt
```

Docker labels affect the image configuration and full image digest, but not the filesystem dmverity layer hashes. Include the labels from the build log when reproducing the complete image digest.

#### Historical build limitations

Some historical images cannot be reproduced bit-for-bit from the source revision and Docker command alone. The current image build has included:

- source checkout modes and modification times in `COPY` layers;
- build timestamps in RPM headers and static archive members;
- generated trust stores whose serialization order can depend on the build host filesystem;
- RPM, TDNF, `ldconfig`, and SQLite state generated during package installation.

Changing only the source mount path does not fix these differences. Replaying the historical wall clock can recover some layers, but host-dependent ordering and database state are not fully described by the build log. Do not silently treat a partial layer match as successful reproduction.

#### Requirements for reproducible future releases

For future images to be independently reproducible:

1. Derive and publish a stable `SOURCE_DATE_EPOCH`, normally from the resolved source commit.
2. Normalize file modes and modification times in every emitted layer.
3. Build RPMs and static archives with deterministic timestamps and ordering.
4. Canonicalize generated trust stores and avoid or canonicalize mutable package-manager, linker-cache, and SQLite state.
5. Publish the resolved source commit, build-context archive, Dockerfile digest, Docker Engine and BuildKit versions, complete build command, base image digest, image digest, and dmverity hashes.
6. Rebuild on a separate clean worker and compare all dmverity layers before publishing the release.

#### Continuous reproducibility check

The `Docker reproducibility` GitHub Actions workflow creates one build-context archive from the checked-out commit. It normalizes path order, ownership, modes, and modification times using `SOURCE_DATE_EPOCH`, which is the source commit timestamp. Two clean GitHub-hosted jobs download that same archive and build the canonical `docker/Dockerfile` independently without shared caches or run-specific BuildKit provenance. A final job compares the complete Docker image IDs and fails if they differ.

The Dockerfile also uses `SOURCE_DATE_EPOCH` to normalize generated files and directories. Transient build artifacts are mounted into the final stage instead of copied into separate layers, and runtime-irrelevant package databases, caches, and development archives are normalized or removed. Following CCF's package-reproduction approach, the RPM build-host, build-time, and file-mtime controls are defined in `app/cpack.cmake` so they apply outside this Dockerfile as well. Base images and fetched source dependencies are pinned to immutable digests or commits.

This gate detects nondeterminism in both filesystem layers and image configuration. It does not replace comparing release dmverity layer hashes with the authenticated security policy.

### 3. Verify UVM

The details of how to reproduce the UVM (to compare it to a `measurement` in the report) are not ready yet.

UVM measurements can be authenticated using [platform endorsements](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64). To get platform endorsements:

```sh
$ curl -s --cacert cacert.pem https://<LEDGER-URL>/node/quotes/self > node-quote.json
$ cat node-quote.json | jq -r '.uvm_endorsements' | base64 -d > uvm_endorsements.cose
... verify cose signing envelope ...
```

UVM endorsement policy can also be seen in `service-join-policy.json`.
