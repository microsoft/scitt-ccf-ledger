# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from typing import cast

import pycose
import pytest
from polars import DataFrame

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.bencher import Bencher, Latency
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

POLICY_REGO = f"""
package policy

issuer_allowed if {{
    input.phdr.cwt.iss == "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13"
}}

svn_undefined if {{
    not input.phdr.cwt.svn
}}

svn_positive if {{
    input.phdr.cwt.svn >= 0
}}

allow if {{
    issuer_allowed
    svn_undefined
}}

allow if {{
    issuer_allowed
    svn_positive
}}
"""


def latency(df: DataFrame) -> Latency:
    return Latency(
        value=cast(float, df["latency (ns)"].mean()),
        high_value=cast(float, df["latency (ns)"].min()),
        low_value=cast(float, df["latency (ns)"].max()),
    )


BF = Bencher()

POLICY = {
    "js": {"policyScript": POLICY_SCRIPT},
    "rego": {"policyRego": POLICY_REGO},
}


@pytest.mark.bencher
@pytest.mark.parametrize("policy", ["js", "rego"])
def test_statement_latency(client: Client, configure_service, policy):
    client.wait_time = 0.1

    configure_service({"policy": POLICY[policy]})

    with open("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rb") as f:
        cts_hashv_cwtclaims = f.read()

    iterations = 10

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement(cts_hashv_cwtclaims)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Test Statement Submission ({policy})")
    print("Signed Statement submitted successfully")
    print(df.describe())

    BF.set(f"Submit Signed Statement ({policy})", latency(df))

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.register_signed_statement(cts_hashv_cwtclaims)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Test Statement Registration End to End ({policy})")
    print("Signed Statement to Transparent Statement")
    print(df.describe())

    BF.set(f"Obtain Transparent Statement ({policy})", latency(df))
