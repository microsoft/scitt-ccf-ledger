ARG CCF_VERSION=5.0.0
FROM ghcr.io/microsoft/ccf/app/dev/sgx:ccf-${CCF_VERSION} as builder
ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE

# Component specific to the CCF app
COPY ./3rdparty/attested-fetch /tmp/attested-fetch/
RUN mkdir /tmp/attested-fetch-build && \
    cd /tmp/attested-fetch-build && \
    CC="clang-11" CXX="clang++-11" cmake -GNinja \
    -DCOMPILE_TARGET="sgx" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app/attested-fetch \
    /tmp/attested-fetch && \
    ninja && ninja install

# Save MRENCLAVE
WORKDIR /usr/src/app/attested-fetch
RUN /opt/openenclave/bin/oesign dump -e libafetch.enclave.so.signed | sed -n "s/mrenclave=//p" > mrenclave.txt

# Build CCF app
COPY ./app /tmp/app/
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC="clang-11" CXX="clang++-11" cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DCOMPILE_TARGET="sgx" \
    -DBUILD_TESTS=OFF \
    -DATTESTED_FETCH_MRENCLAVE_HEX=`cat /usr/src/app/attested-fetch/mrenclave.txt` \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    ninja && ninja install

# Save MRENCLAVE
WORKDIR /usr/src/app
RUN /opt/openenclave/bin/oesign dump -e lib/libscitt.enclave.so.signed | sed -n "s/mrenclave=//p" > mrenclave.txt

FROM ghcr.io/microsoft/ccf/app/dev/sgx:ccf-${CCF_VERSION}
ARG CCF_VERSION

RUN apt update && apt install -y python3 wget

# Install SGX quote library, which is required for out-of-proc attestation.
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt update && apt install -y libsgx-quote-ex
RUN apt remove -y wget

WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/lib/libscitt.enclave.so.signed libscitt.enclave.so.signed
COPY --from=builder /usr/src/app/share/VERSION VERSION
COPY --from=builder /usr/src/app/mrenclave.txt mrenclave.txt

COPY app/fetch-did-web-doc.py /tmp/scitt/fetch-did-web-doc.py
COPY --from=builder /usr/src/app/attested-fetch /tmp/scitt/

WORKDIR /host/node

ENTRYPOINT [ "cchost" ]
