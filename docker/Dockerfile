ARG CCF_VERSION="6.0.12"

# Use fixed image version to ensure reproducibility
ARG BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core:3.0.20250910

FROM ${BASE_IMAGE} AS builder

ARG CCF_VERSION
ARG CCF_PLATFORM
ARG SCITT_VERSION_OVERRIDE

RUN tdnf install -y \
    ca-certificates-1:3.0.0-11.azl3 \
    curl-devel-8.11.1-3.azl3 \
    libuv-devel-1.48.0-1.azl3 && \
    \
    # Download the CCF development package
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_devel_${CCF_VERSION//-/_}_x86_64.rpm" -o ccf.rpm && \
    \
    tdnf install -y ./ccf.rpm

# Build CCF app
COPY ./app /tmp/app/
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-18 CXX=clang++-18 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DCOMPILE_TARGET=${CCF_PLATFORM} \
    -DBUILD_TESTS=OFF \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    ninja && ninja install

FROM ${BASE_IMAGE}

ARG CCF_VERSION
ARG CCF_PLATFORM

WORKDIR /usr/src/app

RUN tdnf install -y \
    ca-certificates-1:3.0.0-11.azl3 \
    tini-0.19.0-22.azl3 \
    tar-1.35-2.azl3 \
    nmap-ncat-7.95-2.azl3 && \
    \
    # Use the CCF runtime package which contains the minimal dependencies for running CCF applications
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_${CCF_VERSION//-/_}_x86_64.rpm" -o ccf.rpm && \
    \
    tdnf install -y \
    ./ccf.rpm && \
    rm ./ccf.rpm && \
    \
    mv "/opt/ccf_${CCF_PLATFORM}/bin/cchost" "/usr/bin/cchost" && \
    \
    tdnf autoremove -y && \
    tdnf clean all && \
    rm -rf /var/cache/tdnf /var/lib/rpm/__db* /var/lib/tdnf/*

COPY --from=builder /usr/src/app/lib/libscitt.${CCF_PLATFORM}.so libscitt.${CCF_PLATFORM}.so
COPY --from=builder /usr/src/app/share/VERSION VERSION

WORKDIR /host/node
COPY docker/start-app.sh start-app.sh
RUN ["chmod", "+x", "start-app.sh"]

# Use tini to handle zombie processes and signal forwarding
# since we use a custom script to start the app 
ENTRYPOINT [ "tini", "--", "./start-app.sh" ]
