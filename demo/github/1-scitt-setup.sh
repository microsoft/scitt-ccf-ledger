#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex 

mkdir -p tmp

SCITT_URL=${SCITT_URL:-"https://127.0.0.1:8000"}

curl -L -o tmp/cacert.pem "https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"
scitt governance propose_ca_certs \
    --name did_web_tls_roots \
    --ca-certs tmp/cacert.pem \
    --url "$SCITT_URL" \
    --member-key workspace/member0_privk.pem \
    --member-cert workspace/member0_cert.pem \
    --development

echo '{ "authentication": { "allow_unauthenticated": true } }' > tmp/configuration.json
scitt governance propose_configuration \
    --configuration tmp/configuration.json \
    --url "$SCITT_URL" \
    --member-key workspace/member0_privk.pem \
    --member-cert workspace/member0_cert.pem \
    --development

TRUST_STORE=tmp/trust_store
mkdir -p $TRUST_STORE

# Get historic parameters to populate the trust store with all the previous service identities
# This is useful to verify entries that have been committed with a previous service identity (e.g., prior to a CCF disaster recovery)
curl -k -f "$SCITT_URL"/parameters/historic > $TRUST_STORE/scitt.json
