# Transparency Service Demo

This demo is a generic proof of concept for a Transparency Service (TS) built on the SCITT CCF ledger. The scripts in this folder let you configure a new SCITT CCF instance, generate and submit COSE-formatted claims, obtain a SCITT receipt for a submitted claim, and verify that the receipt is valid.

## Prerequisites

- The ledger expects payloads to be signed into COSE_Sign1 signature envelopes ("signed statements"). You can set up a custom [X.509 signing certificate](../../docs/configuration.md#x509-roots) locally via the script `0-cacerts-generator.sh`:

    ```bash
    mkdir -p demo-poc/x509_roots
    CACERT_OUTPUT_DIR="demo-poc/x509_roots" ./demo/cts_poc/0-cacerts-generator.sh
    ```
- `0-cacerts-generator.sh` also sets up the configuration file (see the [documentation](../../docs/configuration.md#scitt-configuration)).

- The admin (operator) must be recognized by the TS instance. The member certificate and private key are generated automatically and stored in the `workspace` folder (`member0_cert.pem` and `member0_privk.pem`) **after you start the local instance**.

## Instructions

All the commands must be run from the root of the repository.

### TS Operator

1. Start the instance with a single admin (member):

    ```bash
    export PLATFORM=virtual
    ./build.sh
    ./start.sh
    ```

    Alternatively, set the `SCITT_URL` variable if you are targeting a remote instance that is already deployed and publicly accessible:

    ```
    export SCITT_URL=<address>
    ```

    If the `SCITT_URL` variable is not set, the scripts target a local instance by default (`https://localhost:8000`).

2. Run [`1-operator-demo.sh`](1-operator-demo.sh) to configure the instance.

    ```bash
    MEMBER_CERT_PATH="workspace/member0_cert.pem" MEMBER_KEY_PATH="workspace/member0_privk.pem" SCITT_CONFIG_PATH="demo-poc/x509_roots/configuration.json" ./demo/cts_poc/1-operator-demo.sh
    ```

### TS Client

#### Prepare a payload to sign

Create a file to sign. The payload size limit is 1 MB, so keep it reasonably small.

```bash
echo '{"content":"some demo text"}' > demo-poc/payload.json
```

#### Sign the payload

If you created your own certificate and key as described in the prerequisites, the following command creates a signature:

```bash
ISSUER=$(cat demo-poc/x509_roots/issuer.txt)
CACERT_PATH="demo-poc/x509_roots/cacert.pem" PRIVATE_KEY_PATH="demo-poc/x509_roots/cacert_privk.pem" CLAIM_CONTENT_PATH="demo-poc/payload.json" COSE_CLAIMS_OUTPUT_PATH="demo-poc/payload.sig.cose" DID_X509_ISSUER="$ISSUER" ./demo/cts_poc/2-claim-generator.sh
```

#### Submit the COSE_Sign1 claim file

Submit the COSE claim to the SCITT ledger and verify a receipt for the committed transaction by running the [`3-client-demo.sh`](3-client-demo.sh) script.

The script submits the COSE claim, waits for a receipt to be generated, prints the CBOR receipt in a readable format, and verifies its validity.

```bash
COSE_CLAIMS_PATH="demo-poc/payload.sig.cose" OUTPUT_FOLDER="demo-poc" ./demo/cts_poc/3-client-demo.sh
```

#### Known Issues and Workaround (Local Virtual Build)

- Proposal failing with 403
    > enclave:../src/node/rpc/member_frontend.h:103 - POST /gov/proposals returning error 403: Member m[1e6aee66336c09bf4random8b55398nodeb3d2e08478c092491459a6063] is not active.

    This means the SCITT instance is not configured properly.
    _Workaround:_ To configure locally, run the following command and retry:
    > ./pyscitt.sh governance local_development --url $SCITT_URL