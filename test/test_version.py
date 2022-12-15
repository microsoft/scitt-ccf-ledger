# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import re


def test_get_version(client):
    version = client.get_version()
    scitt_version = version["scitt_version"]
    assert re.match(r"\d+\.\d+\.\d+.*", scitt_version)
