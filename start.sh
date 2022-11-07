#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script launches a single CCF node in sandbox mode.
# It is not secure and must not be used in production.

set -ex

ENCLAVE_TYPE=${ENCLAVE_TYPE:-release}
if [ "$ENCLAVE_TYPE" != "release" ] && [ "$ENCLAVE_TYPE" != "virtual" ]; then
    echo "Invalid enclave type: $ENCLAVE_TYPE"
    exit 1
fi

CCF_DIR=${CCF_DIR:-/opt/ccf}
# TODO: Don't use /tmp
SCITT_DIR=/tmp/scitt

echo "NOTE: Set \$PYTHON_PACKAGE_PATH to /path/to/ccf/repo/python if not using a release"

# Note: 23 worker threads is currently the CCF maximum.
# Note: --sig-tx-interval 10 reduces memory usage when a lot of transactions are in flight.
exec "${CCF_DIR}/bin/sandbox.sh" \
    --package $SCITT_DIR/lib/libscitt \
    --constitution $SCITT_DIR/share/scitt/constitution/scitt.js \
    --verbose \
    --host-log-level info \
    -n "local://0.0.0.0:8000,127.0.0.1:8000" \
    --enclave-type "$ENCLAVE_TYPE" \
    --sig-ms-interval 1000 \
    --sig-tx-interval 10 \
    --worker-threads 0 \
    "$@"
#     --config-file "$(pwd)/ccf-config.sandbox.json" \
