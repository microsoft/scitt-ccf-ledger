# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType

ACTION_DIRECTORY = Path(__file__).resolve().parents[2] / ".github/actions/scitt-sign"


def load_action() -> ModuleType:
    spec = spec_from_file_location("scitt_sign_action", ACTION_DIRECTORY / "action.py")
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
