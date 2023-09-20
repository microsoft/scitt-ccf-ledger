# Reproducibility

The assumption here is that the original build was done using a Docker build. The
goal is to reproduce the same MRENCLAVE value. 

You need a couple pieces of information to begin:

- The source MRENCLAVE value, get it from `https://ledgerurl/node/quotes/self`, e.g.:

    ```json
    {
        "endorsements": "AQAAAAIAAADZL...UMTI6NTU6MTFaAA==",
        "format": "OE_SGX_v1",
        "mrenclave": "b717f0d475e45aa0294f8229ca646316a17dcd7e4ba7f644b353a5d135a6665f",
        "node_id": "247f1df23e22256cc5bc5e8822183117bc5967da41a257d307f9b1153a4f1853",
        "raw": "AwACAAAAAAAIAA...ViynsClboLw="
    }
    ```
- Git commit id that built this version. This is something that has no specifc mapping at the moment. You would need to check the build logs of the SGX Docker image to understand which commit produced the candidate value.

To reproduce the same MRENCLAVE value which would be deployed to CCF 
do a docker build locally but inside of the development version of CCF image:

- Clone the repository and check out the tag or commit id that built the binary which had specific MRENCLAVE
- Identify the expected CCF version by inspecting `./docker/enclave.Dockerfile`
- Run a build inside of the CCF docker image:

    ```
    docker run -it --rm \
        -w /__w/1/s -v $(pwd):/__w/1/s \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --env PLATFORM=sgx \
        --env CXXFLAGS="-ferror-limit=0" \
        --env NINJA_FLAGS="-k 0" \
        mcr.microsoft.com/ccf/app/dev:3.0.12-sgx git config --global --add safe.directory "*" && ./docker/build.sh
    ```
- The build will print the value of MRENCLAVE in the log, similar to:

    ```
    <...>
    mrenclave.txt
    fb2c496416fbab20837fedda0ba6db58d819fa5f5c1b3916062eb2fb9d889966
    ```

