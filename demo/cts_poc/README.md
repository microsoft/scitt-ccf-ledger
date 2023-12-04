# CTS PoC Demo

This demo provides a simple and generic Proof of Concept for a Code Transparency Service (CTS) using the SCITT CCF ledger. The scripts provided in this folder allow configuring a new SCITT CCF instance, generating and submitting claims in COSE format, getting a SCITT receipt for a submitted claim, and verifying the receipt validity. 

## Prerequisites

- A Certificate Authority (CA) certificate and private key are required to configure the SCITT instance. The CA certificate and private key must be provided by the SCITT Operator. For getting a sample pair for testing purposes, you can use the script [cacerts-generator.sh](./cacerts-generator.sh).

    For running the script, you are required to provide the following environment variables:

    - `CACERT_OUTPUT_DIR`: Path to the output directory where the CA certificate and private key files will be stored

    Example command:

    ```bash
    CACERT_OUTPUT_DIR="demo-poc/x509_roots" ./demo/cts_poc/cacerts-generator.sh
    ```

- Access to the CCF member certificate and private key is required to submit proposals to the CCF network. The provided member must be registered into the target CCF network. For a local SCITT instance (e.g., after running the [start.sh](../../start.sh) script), the member certificate and private key are generated automatically and stored in the `workspace` folder (`member0_cert.pem` and `member0_privk.pem`). For a remote SCITT instance, the member certificate and private key must be provided by the SCITT Operator. 

## Instructions

All the commands must be run from the root of the repository.

### CTS Operator

1. Start a new CCF network with a single member. For a local instance, run the following commands (set the `PLATFORM` variable first):

    ```bash
    export PLATFORM=<virtual|sgx>
    ./build.sh
    ./start.sh
    ```

    Alternatively, set the `SCITT_URL` variable if you are targeting a remote instance already deployed and publicly accessible:

    ```
    export SCITT_URL=<address>
    ```

    If the `SCITT_URL` variable is not set, the scripts will target a local instance by default (`http://localhost:8000`).

2. Run the [`operator-demo.sh`](operator-demo.sh) script to activate the CCF member, configure the SCITT instance, and open the CCF network (all operations are idempotent and can be run on an already-configured instance, if needed).

    For running the script, you are required to provide the following environment variables:

    - `MEMBER_CERT_PATH`: Path to the member certificate PEM file.

    - `MEMBER_KEY_PATH`: Path to the member private key PEM file.

    - `CACERT_PATH`: Path to the CA certificate PEM file.

    - `SCITT_CONFIG_PATH`: Path to the SCITT configuration JSON file. The JSON file needs to contain only the content of the `set_scitt_configuration` action. For example:

        ```json
        {
           "authentication": {
               "allow_unauthenticated": true
           }
        }
        ```

        Please refer to [this document](../../docs/configuration.md#scitt-configuration) for more details on the configuration options.

    Example command:

    ```bash
    MEMBER_CERT_PATH="workspace/member0_cert.pem" MEMBER_KEY_PATH="workspace/member0_privk.pem" CACERT_PATH="demo-poc/x509_roots/cacert.pem" SCITT_CONFIG_PATH="demo-poc/configs/scitt_config.json" ./demo/cts_poc/operator-demo.sh
    ```

### CTS client

1. [You can skip this step, if you already have a valid COSE claim to submit] Generate a valid COSE claim to submit to the SCITT ledger by running the [`claim-generator.sh`](claim-generator.sh) script.

    For running the script, you are required to provide the following environment variables:

    - `CACERT_PATH`: Path to the CA certificate PEM file.

    - `PRIVATE_KEY_PATH`: Path to the CA private key PEM file.

    - `CLAIM_CONTENT_PATH`: Path to the JSON/text file containing the claim content. For example:

        ```json
        {
            "foo": "bar"
        }
        ```

    - `COSE_CLAIMS_OUTPUT_PATH`: Path to the output file where the COSE file containing the signed claim will be stored.

    - `CLAIM_CONTENT_TYPE`: Optionally, you can provide the content type of the claim content. If not provided, the content type will be set to `application/json` by default.
    
    Example command:

    ```bash
    CACERT_PATH="demo-poc/x509_roots/cacert.pem" PRIVATE_KEY_PATH="demo-poc/x509_roots/cacert_privk.pem" CLAIM_CONTENT_PATH="demo-poc/claims/claims.json" COSE_CLAIMS_OUTPUT_PATH="demo-poc/claims/claims.cose" ./demo/cts_poc/claim-generator.sh
    ```

2. Submit the COSE claim to the SCITT ledger and verify a receipt for the committed transaction by running the [`client-demo.sh`](client-demo.sh) script.

    The script will submit the COSE claim to the SCITT ledger and will wait for a receipt to be generated. Once the receipt is generated, the script will print the CBOR receipt in a readable format, and verify the receipt validity.

    For running the script, you are required to provide the following environment variables:

    - `COSE_CLAIMS_PATH`: Path to the COSE file containing the signed claim.

    - `OUTPUT_FOLDER`: Path to the folder where script artifacts (e.g., the receipt file) will be stored.

    Example command:

    ```bash
    COSE_CLAIMS_PATH="demo-poc/claims/claims.cose" OUTPUT_FOLDER="test-folder" ./demo/cts_poc/client-demo.sh
    ```
