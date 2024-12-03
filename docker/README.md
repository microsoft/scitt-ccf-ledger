# Build and push SCITT Docker images

This folder contains scripts and utilities to build and run docker images for the SCITT application.

## Build and run docker images

To build a docker image, run the following command from the root of the repository:

```bash
PLATFORM="virtual" ./docker/build.sh
```

To run a docker container using a built image, run the following command from the root of the repository:

```bash
PLATFORM="virtual" ./docker/run-dev.sh
```

Both scripts accept different variables for customization. Please refer to the corresponding scripts for the full list of available variables to use.
