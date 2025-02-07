ARG CCF_VERSION=6.0.0-dev19
FROM ghcr.io/microsoft/ccf/app/dev/virtual:ccf-${CCF_VERSION}  as builder
ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE

# Build CCF app
COPY ./app /tmp/app/
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-15 CXX=clang++-15 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DCOMPILE_TARGET="virtual" \
    -DBUILD_TESTS=OFF \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    ninja && ninja install

FROM ghcr.io/microsoft/ccf/app/run/virtual:ccf-${CCF_VERSION}
ARG CCF_VERSION

RUN apt-get update && apt-get install -y python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/lib/libscitt.virtual.so libscitt.virtual.so
COPY --from=builder /usr/src/app/share/VERSION VERSION

WORKDIR /host/node

ENTRYPOINT [ "cchost" ]
