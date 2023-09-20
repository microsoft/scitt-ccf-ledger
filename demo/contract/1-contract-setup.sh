#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex 

mkdir -p tmp

CONTRACT_URL=${CONTRACT_URL:-"https://127.0.0.1:8000"}

curl -o tmp/cacert.pem "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"

if ! [ -z $OPERATOR ]; then
    scitt governance propose_ca_certs \
        --ca-certs tmp/cacert.pem \
        --url $CONTRACT_URL \
        --member-key workspace/member0_privk.pem \
        --member-cert workspace/member0_cert.pem \
        --name x509_roots \
        --development

    echo '{ "authentication": { "allow_unauthenticated": true } }' > tmp/configuration.json
    scitt governance propose_configuration \
        --configuration tmp/configuration.json \
        --member-key workspace/member0_privk.pem \
        --member-cert workspace/member0_cert.pem \
        --development
fi

TRUST_STORE=tmp/trust_store
mkdir -p $TRUST_STORE

curl -k -f $CONTRACT_URL/parameters > $TRUST_STORE/scitt.json
