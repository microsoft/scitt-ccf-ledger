ARG CCF_VERSION=5.0.6
FROM ghcr.io/microsoft/ccf/app/dev/virtual:ccf-${CCF_VERSION}  as builder
ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE

# Component specific to the CCF app
RUN apt-get update && apt-get install -y libcurl4-openssl-dev
COPY ./3rdparty/attested-fetch /tmp/attested-fetch/
RUN mkdir /tmp/attested-fetch-build && \
    cd /tmp/attested-fetch-build && \
    CC=clang-15 CXX=clang++-15 cmake -GNinja \
    -DCOMPILE_TARGET="virtual" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app/attested-fetch \
    /tmp/attested-fetch && \
    ninja && ninja install

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

COPY app/fetch-did-web-doc.py /tmp/scitt/fetch-did-web-doc.py
COPY --from=builder /usr/src/app/attested-fetch /tmp/scitt/

WORKDIR /host/node

ENTRYPOINT [ "cchost" ]
