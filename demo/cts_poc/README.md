# CTS PoC Demo

This demo provides a simple and generic Proof of Concept for a Code Transparency Service (CTS) using the SCITT CCF ledger. The scripts provided in this folder allow configuring a new SCITT CCF instance, generating and submitting claims in COSE format, getting a SCITT receipt for a submitted claim, and verifying the receipt validity.

## Prerequisites

- A Certificate Authority (CA) certificate is required from the issuer who will be signing and then submitting the COSE_Sign1 signature envelopes. The CA will need to be added to the configuration for CTS to be able to accept the incoming signature envelopes. You can set up custom [X509 roots](../../docs/configuration.md#x509-roots) locally via the script `0-cacerts-generator.sh`:

    ```bash
    mkdir -p demo-poc/x509_roots
    CACERT_OUTPUT_DIR="demo-poc/x509_roots" ./demo/cts_poc/0-cacerts-generator.sh
    ```

- The admin (operator) will need to be recognized by the CTS instance. The member certificate and private key are generated automatically and stored in the `workspace` folder (`member0_cert.pem` and `member0_privk.pem`) after starting the local instance.

- You should have configuration file ready (see [documentation](../../docs/configuration.md#scitt-configuration)), e.g.:

    ```bash
    echo '{ "authentication": { "allowUnauthenticated": true } }' > demo-poc/configuration.json
    ```

## Instructions

All the commands must be run from the root of the repository.

### CTS Operator

1. Start the instance with a single admin (member):

    ```bash
    export PLATFORM=virtual
    ./build.sh
    ./start.sh
    ```

    Alternatively, set the `SCITT_URL` variable if you are targeting a remote instance already deployed and publicly accessible:

    ```
    export SCITT_URL=<address>
    ```

    If the `SCITT_URL` variable is not set, the scripts will target a local instance by default (`https://localhost:8000`).

2. Run the [`1-operator-demo.sh`](1-operator-demo.sh) to configure the instance. Here a pre-generated x509 CA is used `demo-poc/x509_roots/cacert.pem` but you can add your own if using Key Vault. Furthermore, if you have [DID WEB TLS roots](../../docs/configuration.md#did-web-tls-roots) you would like to configure, you can specify the path to the certificate file with the `DID_WEB_ROOT_PATH` environment variable.

    ```bash
    MEMBER_CERT_PATH="workspace/member0_cert.pem" MEMBER_KEY_PATH="workspace/member0_privk.pem" X509_ROOT_PATH="demo-poc/x509_roots/cacert.pem" SCITT_CONFIG_PATH="demo-poc/configuration.json" ./demo/cts_poc/1-operator-demo.sh
    ```

### CTS client

#### Prepare the COSE_Sign1 claim file

You need to have a file to sign. There is a limit on the size of the payload (1MB) so it needs to be reasonably small.

```bash
echo '{"content":"some demo text"}' > demo-poc/payload.json
```

##### Option 1. Use CA certificate and private key

If you created your own certificate and key combination as mentioned in the prerequisites then the following command will create a signature.

```bash
SIGNING_METHOD="cacert" CACERT_PATH="demo-poc/x509_roots/cacert.pem" PRIVATE_KEY_PATH="demo-poc/x509_roots/cacert_privk.pem" CLAIM_CONTENT_PATH="demo-poc/payload.json" COSE_CLAIMS_OUTPUT_PATH="demo-poc/payload.sig.cose" ./demo/cts_poc/2a-claim-generator.sh
```

##### Option 2. Use DID document and private key

**Note**: This step assumes that user already has DID configured. For more details you can also check github DID demo [here](../github/README.md)

If you have a DID document and the corresponding private key, you can use those for creating the signature with a similar command:

```bash
SIGNING_METHOD="did" DID_DOC_PATH="demo-poc/did_roots/did.json" PRIVATE_KEY_PATH="demo-poc/did_roots/key.pem" CLAIM_CONTENT_PATH="demo-poc/payload.json" COSE_CLAIMS_OUTPUT_PATH="demo-poc/payload.sig.cose" ./demo/cts_poc/2a-claim-generator.sh
```

##### Option 3. Use Azure Key Vault certificate and key

You will need the details about your keys and your identity needs to have access to use the keys for signing.

- The CA if there is one or the self signed cert needs to be configured in the instance
- Download the certificates to include in the x5c header:

    ```bash
    az keyvault certificate download --vault-name $VAULT_NAME -n $CERT_NAME -f demo-poc/x509_roots/cacert.pem -e PEM
    ```

- If the certificate has an issuer CA then download it and append it to the same file:

    ```bash
    openssl x509 -noout -text -in demo-poc/x509_roots/cabundle.pem -inform PEM | grep URI
                CA Issuers - URI:http://www.issuer.com/pkiops/certs/2024.crt
    curl -s "http://www.issuer.com/pkiops/certs/2024.crt" | openssl x509 >> demo-poc/x509_roots/cacert.pem
    ```

- Prepare Key Vault config file for the script to use:

    ```bash
    echo '{"keyVaultName": "$VAULT_NAME", "certificateName": "$CERT_NAME", "certificateVersion": "$CERT_VER"}' > demo-poc/akv.json
    ```

- Run the script

    ```bash
    SIGNING_METHOD="akv" CACERT_PATH="demo-poc/x509_roots/cacert.pem" CLAIM_CONTENT_PATH="demo-poc/payload.json" COSE_CLAIMS_OUTPUT_PATH="demo-poc/payload.sig.cose" AKV_CONFIG_PATH="demo-poc/akv.json" ./demo/cts_poc/2a-claim-generator.sh
    ```

#### Submit the COSE_Sign1 claim file

Submit the COSE claim to the SCITT ledger and verify a receipt for the committed transaction by running the [`3-client-demo.sh`](3-client-demo.sh) script.

The script will submit the COSE claim to the SCITT ledger and will wait for a receipt to be generated. Once the receipt is generated, the script will print the CBOR receipt in a readable format, and verify the receipt validity.

```bash
COSE_CLAIMS_PATH="demo-poc/payload.sig.cose" OUTPUT_FOLDER="demo-poc" ./demo/cts_poc/3-client-demo.sh
```

#### Known Issues and Workaround for Local Virtual Build

- If you encounter an "unknown service identity" error during the claim submission process, it may be due to attempting to sign and submit using both DID and X509 simultaneously.
    > ValueError: Unknown service identity '6234efjkfhbsd1random000hash0jkbfdsbfdsjbfg'

    _Workaround:_ To avoid this, ensure you use either X509 or DID exclusively throughout the entire demo.
- Proposal failing with 403
    > enclave:../src/node/rpc/member_frontend.h:103 - POST /gov/proposals returning error 403: Member m[1e6aee66336c09bf4random8b55398nodeb3d2e08478c092491459a6063] is not active.

    This means the scitt instance is not configured properly.
    _Workaround:_ To configure on local, run following command and re-try:
    > ./pyscitt.sh governance local_development --url $SCITT_URL