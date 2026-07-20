# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

pytest_plugins = "test.infra.fixtures"


def pytest_addoption(parser):
    parser.addoption(
        "--enable-perf",
        action="store_true",
        help="Enable performance tests",
    )
    parser.addoption(
        "--enable-dotnet",
        action="store_true",
        help="Enable .NET SDK tests",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "perf: only run test if performance testing is enabled."
    )
    config.addinivalue_line(
        "markers", "dotnet: only run test if .NET SDK testing is enabled."
    )
    config.addinivalue_line("markers", "bencher: benchmark tests using bencher.")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--enable-perf"):
        perf_skip = pytest.mark.skip(
            reason="performance testing was not enabled; use --enable-perf"
        )

        for item in items:
            if "perf" in item.keywords:
                item.add_marker(perf_skip)

    if not config.getoption("--enable-dotnet"):
        dotnet_skip = pytest.mark.skip(
            reason="dotnet testing was not selected; use --enable-dotnet"
        )

        for item in items:
            if "dotnet" in item.keywords:
                item.add_marker(dotnet_skip)
