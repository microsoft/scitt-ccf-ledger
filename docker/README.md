# Build and push SCITT Docker images

This folder contains scripts and utilities to build and run docker images for the SCITT application.

## Build and run docker images

To build a docker image, run the following command from the root of the repository:

```bash
./docker/build.sh
```

To run a docker container using a built image, run the following command from the root of the repository:

```bash
./docker/run-dev.sh
```

Both scripts accept different variables for customization. For example, to build a docker image for non-SGX environments and with a custom docker tag, you can run the following command:

```bash
PLATFORM="virtual" DOCKER_TAG="scitt-virtual" ./docker/build.sh
```

Please refer to the corresponding scripts for the full list of available variables to use.

## Build and push docker images to a container registry

After building a docker image, you can push it to a container registry. For example, to build and push a docker image to an Azure Container Registry (ACR) for the SCITT application running in SGX, you can run the following set of commands:

```bash
ACR="<acr-name>" # Define your ACR name here

# Build docker image for SGX
PLATFORM="sgx" DOCKER_TAG="$ACR.azurecr.io/scitt-sgx:latest" ./docker/build.sh

# Login to ACR
az acr login --name $ACR 

# Push docker image to ACR
docker push $ACR.azurecr.io/scitt-sgx:latest
```
