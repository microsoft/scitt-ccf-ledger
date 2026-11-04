# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import subprocess
from importlib import import_module
from pathlib import Path
from unittest.mock import Mock

import pytest

from .infra.scitt_action import ACTION_DIRECTORY, load_action


@pytest.fixture
def action():
    return load_action()


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_venv_executables(action, monkeypatch, tmp_path, platform):
    monkeypatch.setattr(action.sys, "platform", platform)
    python, scitt = action.venv_executables(tmp_path)
    if platform == "win32":
        assert python == tmp_path / "Scripts/python.exe"
        assert scitt == tmp_path / "Scripts/scitt.exe"
    else:
        assert python == tmp_path / "bin/python"
        assert scitt == tmp_path / "bin/scitt"


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_setup_allocates_unique_outputs(action, monkeypatch, tmp_path, platform):
    runner_temp = tmp_path / "runner temp"
    runner_temp.mkdir()
    output_root = tmp_path / "outputs with spaces;$(echo injected)"
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    monkeypatch.setenv("SCITT_OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(action.sys, "platform", platform)
    create = Mock()
    install = Mock()
    monkeypatch.setattr(action.venv, "create", create)
    monkeypatch.setattr(action.subprocess, "run", install)
    directories = []
    for invocation in range(2):
        github_output = tmp_path / f"github-output-{invocation}"
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        action.setup()
        outputs = dict(
            line.split("=", 1) for line in github_output.read_text().splitlines()
        )
        assert set(outputs) == {"python", "scitt", "output-dir"}
        directory = Path(outputs["output-dir"])
        assert directory.parent == output_root.resolve()
        assert directory.is_dir()
        assert directory not in directories
        directories.append(directory)
        for name in ("signed-statement.cose", "transparent-statement.cose"):
            (directory / name).write_bytes(f"invocation-{invocation}".encode())
        venv_directory = create.call_args.args[0]
        create.assert_called_with(venv_directory, with_pip=True)
        python, scitt = action.venv_executables(venv_directory)
        assert outputs["python"] == str(python)
        assert outputs["scitt"] == str(scitt)
        install.assert_called_with(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--quiet",
                str(ACTION_DIRECTORY.parents[2] / "pyscitt"),
            ],
            check=True,
        )
    for invocation, directory in enumerate(directories):
        for name in ("signed-statement.cose", "transparent-statement.cose"):
            assert (
                directory / name
            ).read_bytes() == f"invocation-{invocation}".encode()
    assert not (tmp_path / "injected").exists()


@pytest.mark.parametrize(
    "value", ["directory\ninjected=value", "directory\rinjected=value"]
)
def test_setup_rejects_output_newlines(action, monkeypatch, tmp_path, value):
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("SCITT_OUTPUT_DIR", value)
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    with pytest.raises(ValueError, match="must not contain newlines"):
        action.setup()
    assert not github_output.exists()


def test_setup_reports_installation_failure(action, monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("SCITT_OUTPUT_DIR", str(tmp_path / "outputs"))
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    monkeypatch.setattr(action.venv, "create", Mock())
    monkeypatch.setattr(
        action.subprocess,
        "run",
        Mock(side_effect=subprocess.CalledProcessError(1, ["pip"])),
    )
    with pytest.raises(subprocess.CalledProcessError):
        action.setup()
    assert not github_output.exists()


@pytest.mark.parametrize("value", ["1.2\ninjected=value", "1.2\rinjected=value"])
def test_write_outputs_rejects_newlines(action, monkeypatch, tmp_path, value):
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    with pytest.raises(ValueError, match="must not contain newlines"):
        action.write_outputs({"transaction-id": value})
    assert not github_output.exists()


def test_action_uses_python_shell_and_setup_output_directory():
    yaml = import_module("yaml")
    action = yaml.safe_load((ACTION_DIRECTORY / "action.yml").read_text())
    steps = [step for step in action["runs"]["steps"] if "run" in step]
    assert len(steps) == 4
    for step in steps:
        assert step["shell"] == "python"
        compile(step["run"], f"action step {step.get('id', 'sign')}", "exec")
        expected = (
            "${{ inputs.output-dir }}"
            if step.get("id") == "setup"
            else "${{ steps.setup.outputs.output-dir }}"
        )
        assert step["env"]["SCITT_OUTPUT_DIR"] == expected
    assert steps[-1]["env"]["SCITT_FILE"] == "${{ inputs.file }}"
    assert "auth-token" not in action["inputs"]
