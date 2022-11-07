ARG CCF_VERSION=2.0.8
FROM mcr.microsoft.com/ccf/app/dev:${CCF_VERSION}-sgx as builder
ARG CCF_VERSION

# Build CCF app
COPY ./app /tmp/app/
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-10 CXX=clang++-10 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DCOMPILE_TARGETS="virtual" \
    -DBUILD_TESTS=OFF \
    /tmp/app && \
    ninja && ninja install

FROM mcr.microsoft.com/ccf/app/run:${CCF_VERSION}-sgx
ARG CCF_VERSION

# curl needed by fetch-did-web-doc-unattested.sh
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/lib/libscitt.virtual.so libscitt.virtual.so

COPY app/fetch-did-web-doc-unattested.sh /tmp/scitt/fetch-did-web-doc-unattested.sh

WORKDIR /host/node

ENTRYPOINT ["cchost"]
