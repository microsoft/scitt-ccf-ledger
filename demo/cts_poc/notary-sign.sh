#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Simple script to generate a container image signature to submit to a SCITT ledger using Notation and a self-signed certificate in Azure Key Vault.
### The script assumes that the user is already logged in to Azure, has proper access and permissions to the given Key Vault and Contaner Registry.
### It is also assumed that the referenced container image is already present in the given Container Registry and that the certificate is present in the given Key Vault.
### Please make sure that the certificate complies with the Notary certificate requirements: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/signature-specification.md#certificate-requirements

set -e

# Variables
: "${AKV_NAME:?"variable not set. Please define the Azure Key Vault name where the self-signed certificate is located"}"
: "${CERTIFICATE_NAME:?"variable not set. Please define the name of the self-signed certificate in Azure Key Vault"}"
: "${CERTIFICATE_VERSION:?"variable not set. Please define the version of the self-signed certificate in Azure Key Vault"}"
: "${ACR_NAME:?"variable not set. Please define the name of the Azure Container Registry where the container image to sign should be found"}"
: "${IMAGE_REPOSITORY:?"variable not set. Please define the image repository in the Azure Container Registry where the container image to sign should be found"}"
: "${SIGNATURE_OUTPUT_PATH:?"variable not set. Please define the path where the COSE signature will be saved to"}"

# Optional variables
IMAGE_TAG=${IMAGE_TAG:-""}
IMAGE_DIGEST=${IMAGE_DIGEST:-""}

# Check if the image tag or digest is provided
if [ -z "$IMAGE_TAG" ] && [ -z "$IMAGE_DIGEST" ]; then
    echo "Either IMAGE_TAG or IMAGE_DIGEST must be provided"
    exit 1
fi

echo -e "\nInstall ORAS CLI"

# Install ORAS CLI
ORAS_VERSION="1.1.0"
curl -LO "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz"
mkdir -p oras-install/
tar -zxf oras_${ORAS_VERSION}_*.tar.gz -C oras-install/
mv oras-install/oras /usr/local/bin/
rm -rf oras_${ORAS_VERSION}_*.tar.gz oras-install/

echo -e "\nInstall Notation CLI"

# Download, extract, and install notation
NOTATION_VERSION="1.0.1"
curl -Lo notation.tar.gz https://github.com/notaryproject/notation/releases/download/v${NOTATION_VERSION}/notation_${NOTATION_VERSION}_linux_amd64.tar.gz
mkdir -p ~/temp_notation_dir
tar xzf notation.tar.gz -C ~/temp_notation_dir

# Copy the Notation binary to the desired bin directory in your $PATH, for example
mv ~/temp_notation_dir/notation /usr/local/bin
rm -rf notation.tar.gz ~/temp_notation_dir

echo -e "\nInstall Notation Azure Key Vault plugin"

# Create a directory for the plugin
mkdir -p ~/.config/notation/plugins/azure-kv

# Download the plugin
curl -Lo notation-azure-kv.tar.gz \
    https://github.com/Azure/notation-azure-kv/releases/download/v${NOTATION_VERSION}/notation-azure-kv_${NOTATION_VERSION}_linux_amd64.tar.gz 

# Extract to the plugin directory
tar xzf notation-azure-kv.tar.gz -C ~/.config/notation/plugins/azure-kv
rm -rf notation-azure-kv.tar.gz

echo -e "\nSign container image with Notation"

# Get the KID of the certificate in Azure Key Vault
KEY_ID=$(az keyvault certificate show -n "$CERTIFICATE_NAME" --vault-name "$AKV_NAME" --version "$CERTIFICATE_VERSION" --query 'kid' -o tsv)

# Login to ACR
az acr login --name "$ACR_NAME"

REGISTRY="$ACR_NAME".azurecr.io

# Concatenate the image repository to either the image tag or digest
if [ -n "$IMAGE_TAG" ]; then
    TBS_IMAGE="$IMAGE_REPOSITORY:$IMAGE_TAG"
else
    TBS_IMAGE="$IMAGE_REPOSITORY@$IMAGE_DIGEST"
fi

IMAGE=$REGISTRY/$TBS_IMAGE

# Sign the image with Notation
notation sign --signature-format cose --id "$KEY_ID" --plugin azure-kv --plugin-config self_signed=true "$IMAGE"

echo -e "\nDownload the image signature from ACR"

# Login to ACR with ORAS using an access token
USER_NAME="00000000-0000-0000-0000-000000000000"
PASSWORD=$(az acr login --name "$ACR_NAME" --expose-token --output tsv --query accessToken)
oras login "$REGISTRY" --username "$USER_NAME" --password "$PASSWORD"

# Find and download the image signature
SIG_MANIFEST_DIGEST=$(oras discover "$IMAGE" --artifact-type application/vnd.cncf.notary.signature -o json | jq -r ".manifests[0].digest")
SIG_BLOB_DIGEST=$(oras manifest fetch "$REGISTRY"/"$IMAGE_REPOSITORY"@"$SIG_MANIFEST_DIGEST" | jq -r ".layers[0].digest")
oras blob fetch --output "$SIGNATURE_OUTPUT_PATH" "$REGISTRY"/"$IMAGE_REPOSITORY"@"$SIG_BLOB_DIGEST"

echo -e "\nScript completed successfully"
