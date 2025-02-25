ARG CCF_VERSION=6.0.0-dev20
FROM ghcr.io/microsoft/ccf/app/dev/virtual:ccf-${CCF_VERSION}  as builder
ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE
# remove all files that reference the ppa
RUN find /etc/apt -type f -exec grep -Ril 'ppa.launchpad.net' {} \; -exec rm -f {} +
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
WORKDIR /usr/src/app
# remove all files that reference the ppa
RUN find /etc/apt -type f -exec grep -Ril 'ppa.launchpad.net' {} \; -exec rm -f {} +
COPY --from=builder /usr/src/app/lib/libscitt.virtual.so libscitt.virtual.so
COPY --from=builder /usr/src/app/share/VERSION VERSION
WORKDIR /host/node
ENTRYPOINT [ "cchost" ]
