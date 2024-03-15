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
    echo '{ "authentication": { "allow_unauthenticated": true } }' > demo-poc/configuration.json
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

##### Option 4. Use Notary and Azure Key Vault (for ACR container image signatures only)

If you want to generate a signature with a self-signed certificate in Azure Key Vault for a container image present in an Azure Container Registry, you can use the [2b-notary-sign.sh](2b-notary-sign.sh) script. The script uses [Notation](https://github.com/notaryproject/notation) to create the image signature in ACR using the input Key Vault certificate. It then uses [ORAS](https://oras.land/) to fetch the image signature as a COSE object, ready to be submitted to a SCITT ledger.

The process to sign a container image with Notation and Azure Key Vault using a self-signed certificate is documented [here](https://learn.microsoft.com/azure/container-registry/container-registry-tutorial-sign-build-push). Please note that a pre-requisite for this script is to have a Key Vault instance with a self-signed certificate compatible with the [Notary Project certificate requirements](https://github.com/notaryproject/specifications/blob/main/specs/signature-specification.md#certificate-requirements). You can find more information on how to create a compatible self-signed certificate in AKV [here](https://learn.microsoft.com/azure/container-registry/container-registry-tutorial-sign-build-push#create-a-self-signed-certificate-in-akv-azure-cli). 

For running the script, you can provide the following environment variables:

- `AKV_NAME`: Name of the Azure Key Vault instance where the certificate is stored.
- `CERTIFICATE_NAME`: Name of the certificate stored in the Azure Key Vault instance.
- `CERTIFICATE_VERSION`: Version of the certificate stored in the Azure Key Vault instance.
- `ACR_NAME`: Name of the Azure Container Registry instance where the image is stored.
- `IMAGE_REPOSITORY`: ACR repository of the image to sign.
- `IMAGE_TAG`: Tag of the image to sign (if the digest is not provided).
- `IMAGE_DIGEST`: Digest of the image to sign.
- `SIGNATURE_OUTPUT_PATH`: Path to the output file where the COSE file containing the image signature will be stored.

#### Submit the COSE_Sign1 claim file

Submit the COSE claim to the SCITT ledger and verify a receipt for the committed transaction by running the [`3-client-demo.sh`](3-client-demo.sh) script.

The script will submit the COSE claim to the SCITT ledger and will wait for a receipt to be generated. Once the receipt is generated, the script will print the CBOR receipt in a readable format, and verify the receipt validity.

```bash
COSE_CLAIMS_PATH="demo-poc/payload.sig.cose" OUTPUT_FOLDER="demo-poc" ./demo/cts_poc/3-client-demo.sh
```

