# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from pyscitt.client import ServiceError


def service_error(match: str):
    return pytest.raises(ServiceError, match=match)
