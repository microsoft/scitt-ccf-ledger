# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--enable-prefix-tree",
        action="store_true",
        help="Enable tests which depend on prefix tree support",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "prefix_tree: only run test if prefix tree support is enabled."
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--enable-prefix-tree"):
        skip = pytest.mark.skip(reason="prefix tree support was not enabled")
        for item in items:
            if "prefix_tree" in item.keywords:
                item.add_marker(skip)
