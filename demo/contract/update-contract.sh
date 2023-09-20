#/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if [[ -z "${TDP_USERNAME}" ]]; then
  echo "No TDP username specified"
  exit 1
fi

if [[ -z "${TDC_USERNAME}" ]]; then
  echo "No TDC username specified"
  exit 1
fi

export TDP_DID="did:web:$TDP_USERNAME.github.io"
export TDC_DID="did:web:$TDC_USERNAME.github.io"

TMP=$(jq '.tdc = env.TDC_DID' demo/contract/contract.json)
TMP=`echo $TMP | jq '.tdps[0] = env.TDP_DID'`
TMP=`echo $TMP | jq '.datasets[0].provider = env.TDP_DID'`
TMP=`echo $TMP | jq '.datasets[1].provider = env.TDP_DID'`
TMP=`echo $TMP | jq '.datasets[2].provider = env.TDP_DID'`
echo $TMP > ./tmp/contracts/contract.json
