# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from typing import cast

import pytest
from polars import DataFrame

from pyscitt.client import Client

from .infra.bencher import Bencher, Latency
from .policies import SAMPLE_POLICY


def latency(df: DataFrame) -> Latency:
    return Latency(
        value=cast(float, df["latency (ns)"].mean()),
        high_value=cast(float, df["latency (ns)"].min()),
        low_value=cast(float, df["latency (ns)"].max()),
    )


BF = Bencher()


@pytest.mark.bencher
@pytest.mark.parametrize("policy", ["js", "rego"])
def test_statement_latency(client: Client, configure_service, policy):
    client.wait_time = 0.1

    configure_service({"policy": SAMPLE_POLICY[policy]})

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
