# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import re


def test_get_version(client):
    version_response = client.get_version()
    version = version_response["version"]
    assert re.match(r"\d+\.\d+\.\d+.*", version)
