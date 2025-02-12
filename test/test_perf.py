# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from typing import cast

import pytest
from polars import DataFrame

from pyscitt.client import Client

from . import policies
from .infra.bencher import Bencher, Latency


def latency(df: DataFrame) -> Latency:
    return Latency(
        value=cast(float, df["latency (ns)"].mean()),
        high_value=cast(float, df["latency (ns)"].min()),
        low_value=cast(float, df["latency (ns)"].max()),
    )


BF = Bencher()


@pytest.mark.bencher
@pytest.mark.parametrize("lang", ["js", "rego"])
def test_statement_latency(client: Client, configure_service, lang):
    client.wait_time = 0.1

    configure_service({"policy": policies.SAMPLE[lang]})

    with open("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rb") as f:
        cts_hashv_cwtclaims = f.read()

    iterations = 10

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.submit_signed_statement(cts_hashv_cwtclaims)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Test Statement Submission ({lang})")
    print("Signed Statement submitted successfully")
    print(df.describe())

    BF.set(f"Submit Signed Statement ({lang})", latency(df))

    latency_ns = []
    for i in range(iterations):
        start = time.time()
        client.register_signed_statement(cts_hashv_cwtclaims)
        latency_ns.append((time.time() - start) * 1_000_000_000)

    df = DataFrame({"latency (ns)": latency_ns})
    print(f"Test Statement Registration End to End ({lang})")
    print("Signed Statement to Transparent Statement")
    print(df.describe())

    BF.set(f"Obtain Transparent Statement ({lang})", latency(df))
