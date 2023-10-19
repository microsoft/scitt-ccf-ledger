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

After building a docker image, you can push it to a container registry (e.g., Azure Container Registry). You can use the `push_image.sh` script to automatically build and push the image to ACR:

```bash
# Build docker image for SGX
./docker/push_image.sh
```
