ARG CCF_VERSION=3.0.2
FROM mcr.microsoft.com/ccf/app/dev:${CCF_VERSION}-virtual as builder
ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE

# Build CCF app
COPY ./app /tmp/app/
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-10 CXX=clang++-10 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DCOMPILE_TARGET="virtual" \
    -DBUILD_TESTS=OFF \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    ninja && ninja install

FROM mcr.microsoft.com/ccf/app/run:${CCF_VERSION}-virtual
ARG CCF_VERSION

# curl needed by fetch-did-web-doc-unattested.sh
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/lib/libscitt.virtual.so libscitt.virtual.so
COPY --from=builder /usr/src/app/share/VERSION VERSION

COPY app/fetch-did-web-doc-unattested.sh /tmp/scitt/fetch-did-web-doc-unattested.sh

WORKDIR /host/node

ENTRYPOINT ["cchost"]
