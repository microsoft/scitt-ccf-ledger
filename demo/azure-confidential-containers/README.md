# Running on Azure

This guide shows how to deploy and use the service on Azure Confidential Computing. It also shows how to sign payloads so they pass registration policies.

You will:

1. Build and publish a container image.
2. Upload configuration files to an Azure file share.
3. Deploy the service using an ARM template.
4. Finish setup by opening the service and configuring policies.

## Limitations

The Azure CLI `confcom` extension does not run on macOS, so you cannot deploy this demo from macOS using `az`.

If you are on macOS, run these steps from a Linux machine or a Linux VM.

This demo deploys a single ledger node. In production, you should run at least three nodes so the service can recover if one node fails. For background, see https://microsoft.github.io/CCF/main/operations/start_network.html.

This demo uses the service IP address directly (no DNS). That makes end-to-end TLS verification harder, because the service certificate typically does not include the public IP address in its Subject Alternative Name (SAN). In practice, this means tools like `curl` may reject the connection unless you disable hostname verification.

## Prerequisites

- A Linux environment to run the commands in this guide
- An Azure account with permission to create resources
- Install Azure CLI
- Install the Azure CLI `confcom` extension (used to compute a security policy for the confidential container)

    ```bash
    az extension add -n confcom
    ```

- Create a resource group in the North Europe region
    
    ```bash
    az group create --name demo-cc-ne --location northeurope
    ```

## Build and publish the container image

The deployment requires a container image published in an accessible container registry.

### Build the container image

1. Clone the repository

    ```bash
    git clone https://github.com/microsoft/scitt-ccf-ledger.git && cd scitt-ccf-ledger
    ```

2. Build the Docker image

    ```bash
    ./docker/build.sh
    ```

3. Tag the image with an accessible remote repository reference, e.g. `username/demo-scitt-ccf-ledger`

    ```bash
    docker tag scitt-snp username/demo-scitt-ccf-ledger:latest
    ```

4. Push the image layers

    ```bash
    docker push username/demo-scitt-ccf-ledger:latest
    ```

### Prepare startup configuration

This is a CCF application, and it requires a configuration file at startup. For more details, see https://microsoft.github.io/CCF/main/operations/configuration.html.

```bash
# directory to share with a running container
mkdir -p "workspace"
# create a config file for the ledger
cp ./docker/dev-config.tmpl.json workspace/dev-config.json
# update values in the config file
sed -i "s/%ENCLAVE_PLATFORM%/SNP/g" workspace/dev-config.json
sed -i "s/%ENCLAVE_TYPE%/Release/g" workspace/dev-config.json
sed -i "s/%ENCLAVE_FILE%/libscitt.snp.so/g" workspace/dev-config.json
sed -i "s/%CCF_PORT%/8000/g" workspace/dev-config.json

# add constitution files
cp -r ./app/constitution workspace

# generate administrator/operator keys
pushd workspace
./../docker/keygenerator.sh --name member0 --gen-enc-key
popd

# configure attestation part for CCF
# This depends on Azure-specific environment variables for confidential containers
# docs: https://microsoft.github.io/CCF/main/operations/platforms/snp.html
# example: https://github.com/microsoft/CCF/blob/main/samples/config/start_config_aci_sev_snp.json
SNP_ATTESTATION_CONTENT='{ "snp_endorsements_servers": [ { "type": "THIM", "url": "$Fabric_NodeIPOrFQDN:2377" } ], "snp_security_policy_file": "$UVM_SECURITY_CONTEXT_DIR/security-policy-base64", "snp_uvm_endorsements_file": "$UVM_SECURITY_CONTEXT_DIR/reference-info-base64", "snp_endorsements_file": "$UVM_SECURITY_CONTEXT_DIR/host-amd-cert-base64"}' 
sudo apt install jq
jq --argjson content "$SNP_ATTESTATION_CONTENT" '.attestation = $content' workspace/dev-config.json > tmp.json && mv tmp.json workspace/dev-config.json
```

### Upload startup configuration to Azure

Create a storage account and upload the configuration files. Azure will mount this file share into the container at startup.

```bash
az storage account create --resource-group demo-cc-ne --name democcnescittccf --location northeurope --sku Standard_LRS
az storage share create --name configshare --account-name democcnescittccf
az storage file upload-batch --destination configshare --source workspace --account-name democcnescittccf
```

## ARM template deployment

At this point you have a container image in a registry, and a set of configuration files ready to mount into the container. Next, deploy and start the image as a confidential container.

### Update the ARM template

Update the image name and replace `username/demo-scitt-ccf-ledger:latest` with your own.

This demo assumes the image is in Docker Hub. If you use a different registry (or a private repository), update the template accordingly.

Store registry variables for the deployment:

```bash
export DOCKER_USERNAME=changeme
export DOCKER_PASS=dckr_pat_XXXXXX
```

### Compute security policy

Recompute the security policy and set it in the template. This policy captures the container environment details and image layer hashes.

```bash
az confcom acipolicygen -a arm-template.json
```

### Deploy template

Deploy the template. Make sure the parameters are correctly populated with your registry credentials and storage account details:

```bash
az deployment group create --resource-group demo-cc-ne --template-file arm-template.json --parameters storageAccountName=democcnescittccf --parameters storageAccountKey=$(az storage account keys list --resource-group demo-cc-ne --account-name democcnescittccf --query "[0].value" -o tsv) --parameters fileShareName=configshare --parameters registryUsername=$DOCKER_USERNAME --parameters registryPassword=$DOCKER_PASS
```

### Inspect deployment

To verify the deployment, check that the container was created successfully and then review the logs.

#### Logs

```bash
az container logs --name scitt-ccf-ledger-demo --resource-group demo-cc-ne
```

```log
2026-01-20T12:00:28.639928Z -0.041 0   [info ] CCF/src/node/node_state.h:2544       | [global] Opening members frontend
2026-01-20T12:00:28.639936Z -0.041 0   [info ] CCF/src/node/rpc/frontend.h:984      | Opening frontend
2026-01-20T12:00:28.640723Z -0.042 0   [info ] CCF/src/node/node_state.h:2573       | Executing global hook for service table at 1, to service status 1. Cert is:
-----BEGIN CERTIFICATE-----
MIIBzzCCAVSgAwIBAgIRAIaSkwX1b/ynn92a9kZu7oEwCgYIKoZIzj0EAwMwFjEU
...
RpLMLMApG0GJC4rIkhfN8hf/rzo/eJVdV6PvEzdP2Q+Byos=
-----END CERTIFICATE-----
```

**Troubleshooting:** 
- If the logs show a failure related to confidential parameter verification, make sure you recomputed the security policy immediately before deployment.

#### Parameters

Get the container parameters (including the public IP address):

```bash
az container show --name scitt-ccf-ledger-demo --resource-group demo-cc-ne
...
"ip": "20.67.206.104"
```

Store the IP to be later used in API calls:

```bash
export SCITT_URL=https://20.67.206.104:8000
```

### Download service certificate

Download the generated service certificate for end-to-end TLS. It will be present in the file share mounted to the container. You can also copy/paste it from the container logs.

```bash
az storage file download --path service_cert.pem --share-name configshare --account-name democcnescittccf
```

#### (Optional) Test the service endpoint

Because this demo uses an IP address (not DNS), the node certificate may not match the host name that `curl` verifies. The node certificate will contain SAN entries that were provided in the startup configuration under `node_certificate.subject_alt_names`.

- To avoid hostname verification issues, you can disable it with the `-k` flag in `curl`.

    ```bash
    curl --cacert service_cert.pem -k "$SCITT_URL/version"
    ```

- Alternatively, you can use `--resolve` to map a expected DNS name to the IP address.

    ```bash
    curl --cacert service_cert.pem --resolve "ccf.dummy.com:8000:20.67.206.104" https://ccf.dummy.com:8000/version"
    ```

## Open service

When the container starts, the service frontend is "closed" (not usable yet) and needs runtime configuration. Before you do that, install the CLI locally.

1. Install the CLI

    ```bash
    python3 -m venv "venv"
    source venv/bin/activate
    pip install --disable-pip-version-check -q -e ./pyscitt
    ```

2. Activate the member identity (operator) that is allowed to update the configuration.

    ```bash
    scitt governance activate_member \
        --url "$SCITT_URL" \
        --member-key "workspace/member0_privk.pem" \
        --member-cert "workspace/member0_cert.pem" \
        --development
    ```

3. Set the ledger runtime configuration (authentication and registration policy). Make it restrictive for now; you can loosen it later when you prepare a payload signer.

    ```bash
    # create restrictive configuration
    echo '{ "authentication": { "allowUnauthenticated": false }, "policy": { "policyScript": "export function apply(phdr) { return false }" }}' > runtime-config-restrictive.json
    # update configuration
    scitt governance propose_configuration \
        --url "$SCITT_URL" \
        --configuration "runtime-config-restrictive.json" \
        --member-key "workspace/member0_privk.pem" \
        --member-cert "workspace/member0_cert.pem" \
        --development
    ```

4. Open the service to public clients

    ```bash
    scitt governance propose_open_service \
        --url "$SCITT_URL" \
        --member-key "workspace/member0_privk.pem" \
        --member-cert "workspace/member0_cert.pem" \
        --next-service-certificate "service_cert.pem" \
        --development
    ```

## Sign and submit payloads

For a worked example of signing payloads and updating the registration policy, see [transparency-service-poc](../transparency-service-poc/README.md).

