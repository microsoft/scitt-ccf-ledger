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


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "perf: only run test if performance testing is enabled."
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--enable-perf"):
        perf_skip = pytest.mark.skip(reason="performance testing was not enabled")

        for item in items:
            if "perf" in item.keywords:
                item.add_marker(perf_skip)
