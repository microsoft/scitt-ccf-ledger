#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -x

# This script invokes attested-fetch, and, if successful, POSTs the response
# back to the CCF app. The callback URL to the CCF app is given as a command
# line argument.

# TODO remove this again once CCF logs output from subprocesses
exec >  >(tee -i /tmp/scitt-fetch-did-web-doc-attested.log)
exec 2>&1

AFETCH_DIR="/tmp/scitt"
url=$1
nonce=$2
callback_url=$3
out_path=$(mktemp "${AFETCH_DIR}/out.XXXXXX")
trap "rm -f ${out_path}" 0 2 3 15

"${AFETCH_DIR}/afetch" \
    "${AFETCH_DIR}/libafetch.enclave.so.signed" \
    "${out_path}" "${url}" "${nonce}"

exit_code=$?
if [ $exit_code -ne 0 ]; then
  echo "attested-fetch failed"
  exit 1
fi

cat "${out_path}"

retries_left=3
while [ $retries_left -gt 0 ]; do
    curl -k -f --data-binary "@${out_path}" -H "Content-Type: application/json" "${callback_url}"
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        break
    fi
    echo "curl failed, retrying..."
    ((retries_left--))
    sleep 1
done

if [ $exit_code -ne 0 ]; then
    # Send again without -f to get server output for debugging.
    curl -k --data-binary "@${out_path}" -H "Content-Type: application/json" "${callback_url}"
    echo "curl failed: ${callback_url}"
    exit 2
fi
