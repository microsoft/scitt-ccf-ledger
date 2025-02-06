# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time

import pycose
import pytest
from polars import DataFrame

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority

POLICY_SCRIPT = f"""
export function apply(profile, phdr) {{
if (profile !== "IETF") {{ return "This policy only accepts IETF did:x509 signed statements"; }}

// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat < (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

return true;
}}"""


@pytest.mark.isolated_test
def test_statement_latency(client: Client, configure_service):

    configure_service({"policy": {"policyScript": POLICY_SCRIPT}})

    with open("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rb") as f:
        cts_hashv_cwtclaims = f.read()

    iterations = 10

    latency_s = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement(cts_hashv_cwtclaims)
        latency_s.append(time.time() - start)

    df = DataFrame({"latency (s)": latency_s})
    print("Test Statement Submission")
    print("Signed Statement submitted successfully")
    print(df.describe())

    latency_s = []
    for i in range(iterations):
        start = time.time()
        client.register_signed_statement(cts_hashv_cwtclaims)
        latency_s.append(time.time() - start)

    df = DataFrame({"latency (s)": latency_s})
    print("Test Statement Registration End to End")
    print("Signed Statement to Transparent Statement")
    print(df.describe())
