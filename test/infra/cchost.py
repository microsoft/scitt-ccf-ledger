# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import asyncio
import json
import os
import shutil
import signal
import ssl
import subprocess
from pathlib import Path
from typing import List, Optional

import aiotools
from loguru import logger as LOG

from pyscitt import crypto

from .async_utils import EventLoopThread, race_tasks

# Register some log levels used by cchost that have, by default, no equivalent
# in loguru.
LOG.level("FAIL", no=60, color="<red>")
LOG.level("FATAL", no=60, color="<red>")


class CCHost(EventLoopThread):
    binary: str
    enclave_file: Path
    platform: str
    workspace: Path
    constitution: List[Path]

    # Port numbers which cchost will used to listen for incoming connections.
    # If 0, a random port number will be assigned by the OS.
    listen_rpc_port: int
    listen_node_port: int

    # Cryptographic material of the member
    member_private_key: crypto.Pem
    member_cert: crypto.Pem
    encryption_private_key: crypto.Pem

    # The effective port number on which cchost is listening. This is equal
    # to listen_rpc_port, unless the latter was zero in which case this field
    # reflects the randomly assigned port number.
    #
    # This field is only available after the service has started, and may
    # change each time `restart()` is called.
    rpc_port: int

    restart_request: asyncio.Event

    faketime_file: Optional[Path]
    faketime_lib: Optional[Path]
    clock_offset: int

    def __init__(
        self,
        binary: str,
        platform: str,
        enclave_file: Path,
        workspace: Path,
        constitution: List[Path],
        rpc_port: int = 0,
        node_port: int = 0,
        enable_faketime: bool = False,
    ):
        super().__init__()

        self.binary = binary
        self.listen_rpc_port = rpc_port
        self.listen_node_port = node_port
        self.platform = platform

        # Make the path absolutes, so they keep working even after we change
        # working directory when running cchost.
        self.enclave_file = enclave_file.absolute()
        self.workspace = workspace.absolute()
        self.constitution = [f.absolute() for f in constitution]

        if not self.enclave_file.exists():
            raise ValueError(f"Enclave file at {self.enclave_file} does not exist")

        self.member_private_key, _ = crypto.generate_keypair(kty="ec")
        self.member_cert = crypto.generate_cert(self.member_private_key)
        self.encryption_private_key, encryption_public_key = crypto.generate_keypair(
            kty="rsa"
        )

        self.workspace.joinpath("member0_privk.pem").write_text(self.member_private_key)
        self.workspace.joinpath("member0_cert.pem").write_text(self.member_cert)
        self.workspace.joinpath("member0_enc_privk.pem").write_text(
            self.encryption_private_key
        )
        self.workspace.joinpath("member0_enc_pubk.pem").write_text(
            encryption_public_key
        )

        self.restart_request = self._create_event()

        self.faketime_file = None
        self.clock_offset = 0
        if enable_faketime:
            # Unfortunately there isn't really a portable way of finding this path.
            # Hardcode what works on the CI images we use, and allow it to be overridden.
            faketime_lib = Path(
                os.getenv(
                    "LIBFAKETIME",
                    "/usr/lib/x86_64-linux-gnu/faketime/libfaketimeMT.so.1",
                )
            )

            if faketime_lib.exists():
                self.faketime_lib = faketime_lib
                self.faketime_file = self.workspace.joinpath("faketime")
                self.faketime_file.write_text("+0")
                LOG.info("Using faketime library at {}", self.faketime_lib)
            else:
                LOG.warning("Could not find faketime library")

    def restart(self) -> None:
        self._set_event(self.restart_request)
        self.wait_ready()

    async def run(self) -> None:
        """
        Invoked by EventLoopThread when the context manager is entered.

        Runs cchost in a loop, restarting it every time a restart request is
        received. Aside from errors, this function only returns when the task
        is cancelled, which happens when the EventLoopThread context manager is
        exited.
        """
        first_start = True
        while True:
            self._populate_workspace(start=first_start)
            first_start = False

            # We use race_tasks as a reliable way to make the restart_request
            # signal cancel the _start_process task, which in turn will kill
            # the process. _start_process never terminates gracefully, so we
            # don't expect it to ever win the race.
            self.restart_request.clear()
            await race_tasks(
                self.restart_request.wait(),
                self._start_process(),
            )

    def advance_time(self, *, seconds: int) -> None:
        if self.faketime_file is None:
            raise RuntimeError("faketime was not enabled")

        self.clock_offset += seconds
        self.faketime_file.write_text(f"+{self.clock_offset}")

    async def _start_process(self) -> None:
        """
        Start and monitor a cchost process.

        Once the service is accepting connections, EventLoopThread's
        `set_ready` method is called. The service will keep running until the
        task is cancelled.
        """

        # Ensure SGX_AESM_ADDR is not set when starting cchost.
        cchost_env = os.environ.copy()
        cchost_env.pop("SGX_AESM_ADDR", None)

        if self.faketime_file is not None:
            cchost_env["LD_PRELOAD"] = str(self.faketime_lib)
            cchost_env["FAKETIME_TIMESTAMP_FILE"] = str(self.faketime_file)
            cchost_env["FAKETIME_NO_CACHE"] = "1"

        LOG.debug("Starting cchost process...")
        process = await asyncio.create_subprocess_exec(
            self.binary,
            "--config",
            self.workspace / "config.json",
            cwd=self.workspace,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=cchost_env,
        )

        try:
            async with aiotools.TaskGroup() as tg:
                # These sub-tasks will get cancelled automatically when this one
                # is. They only get cancelled after we leave the `async with` block,
                # which allows us to wait for the process to quit first. This
                # works nicely as it makes sure the log processing tasks get to see
                # the final log messages emitted by cchost on its way out.
                tg.create_task(self._process_stdout(process.stdout))
                tg.create_task(self._process_stderr(process.stderr))
                tg.create_task(self._wait_ready())

                await self._wait_for_process(process)

        finally:
            # Old asyncio versions don't always clean up the subprocess'
            # correctly. The cleanup is delayed and frequently happens after
            # the event loop has closed, which leads to noise on out console
            # output. The only readily available workaround it to poke at the
            # implementation details of the process object, and call close() on
            # the transport manually.
            #
            # This is fixed in Python 3.11.1, at which point we won't have to do
            # anything. See https://github.com/python/cpython/issues/88050.
            process._transport.close()  # type: ignore[attr-defined]

    async def _wait_for_process(self, process: asyncio.subprocess.Process) -> None:
        """
        Wait for the cchost process to terminate.

        If this task is cancelled, the process will be killed, gracefully at
        first and then forcibly. If instead the process terminates of its own
        volition, an exception is raised.
        """
        try:
            await process.wait()
        finally:
            try:
                process.terminate()
                try:
                    LOG.info("Waiting for cchost process to terminate gracefully")
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    LOG.info(
                        "cchost process failed to terminate gracefully, sending SIGKILL"
                    )
                    process.kill()
                    await process.wait()

            except ProcessLookupError:
                # This can happen if the process is already dead. We could check
                # if process.returncode is not None ahead of time, but this
                # might be vulnerable to race conditions: https://stackoverflow.com/a/64342461
                pass

            if process.returncode != 0:
                raise RuntimeError(
                    f"cchost process terminated with a non-zero status: {process.returncode}"
                )

        # The only way we can reach this point is if cchost terminates with a
        # zero return code, and our task was not cancelled (otherwise the wait
        # would have been aborted by a CancelledError).
        raise RuntimeError("cchost process terminated early")

    async def _process_stdout(self, stream):
        while True:
            line = await stream.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.decoder.JSONDecodeError:
                LOG.error("Log line is not JSON: {}", line)
            else:
                # Translate the CCF log message into something usable by loguru.
                # We map the filename to function, even though loguru supports filenames,
                # because the latter isn't printed by default.
                # We use the presence of an enclave timestamp (e_ts) to distinguish
                # between host and enclave messages.
                level = msg["level"].upper()
                context = {
                    "function": msg["file"],
                    "line": msg["number"],
                    "name": "enclave" if "e_ts" in msg else "host",
                }
                LOG.patch(lambda r: r.update(context)).log(level, "{}", msg["msg"])

    async def _process_stderr(self, stream):
        while True:
            line = await stream.readline()
            if not line:
                break
            LOG.warning("{}", line)

    async def _wait_ready(self):
        """
        Monitor the service and set the `ready` flag once it accepts connections.
        """

        LOG.info("Waiting for cchost process to become ready")
        while True:
            port = await self._poll_ready()

            if port is not None:
                LOG.info(f"cchost is ready and listening on port {port}")
                self.rpc_port = port
                self.set_ready()
                return

            await asyncio.sleep(0.5)

    async def _poll_ready(self) -> Optional[int]:
        """
        Check if the service is ready yet, by establishing a connection to it.

        Returns the service's port number if it is ready, and None otherwise.
        """
        ssl_ctx = ssl.SSLContext()
        try:
            # cchost writes its actual RPC port to this file. This works even if
            # it tried to bind on port 0 and was given a random port by the
            # kernel.
            with open(self.workspace / "rpc_addresses.json") as f:
                addresses = json.load(f)
                hostname, port = addresses["rpc"].split(":")

            await asyncio.open_connection("127.0.0.1", int(port), ssl=ssl_ctx)

            return int(port)
        except OSError:
            # Assume the service is not ready yet. Either we failed to read the
            # ports file, or we couldn't establish a connection to it.
            return None

    def _populate_workspace(self, start=True):
        service_cert = self.workspace / "service_cert.pem"
        previous_service_cert = self.workspace / "previous_service_cert.pem"

        if service_cert.exists():
            service_cert.rename(previous_service_cert)

        PLATFORMS = {
            "sgx": {"platform": "SGX", "type": "Release"},
            "virtual": {"platform": "Virtual", "type": "Virtual"},
        }

        config = {
            "enclave": {
                "file": str(self.enclave_file),
                **PLATFORMS[self.platform],
            },
            "network": {
                "rpc_interfaces": {
                    "rpc": {
                        "bind_address": f"0.0.0.0:{self.listen_rpc_port}",
                    }
                },
                "node_to_node_interface": {
                    "bind_address": f"0.0.0.0:{self.listen_node_port}"
                },
            },
            "logging": {"format": "Json", "host_level": "Info"},
            "output_files": {
                "rpc_addresses_file": str(self.workspace / "rpc_addresses.json"),
            },
        }

        if start:
            config["command"] = {
                "type": "Start",
                "service_certificate_file": str(service_cert),
                "start": {
                    "constitution_files": [str(f) for f in self.constitution],
                    "members": [
                        {
                            "certificate_file": str(
                                self.workspace / "member0_cert.pem"
                            ),
                            "encryption_public_key_file": str(
                                self.workspace / "member0_enc_pubk.pem"
                            ),
                        }
                    ],
                },
            }
        else:
            config["command"] = {
                "type": "Recover",
                "service_certificate_file": str(service_cert),
                "recover": {
                    "initial_service_certificate_validity_days": 1,
                    "previous_service_identity_file": str(previous_service_cert),
                },
            }

        with open(self.workspace / "config.json", "w") as f:
            json.dump(config, f)


def get_enclave_path(platform: str, enclave_package) -> Path:
    ENCLAVE_SUFFIX = {
        "virtual": "virtual.so",
        "sgx": "enclave.so.signed",
    }
    return Path(f"{enclave_package}.{ENCLAVE_SUFFIX[platform]}")


def get_default_cchost_path(platform: str) -> Path:
    return Path(f"/opt/ccf_{platform}/bin/cchost")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cchost", help="Path to the cchost binary")
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port on which cchost will listen for RPC",
    )
    parser.add_argument(
        "--node-port",
        type=int,
        default=0,
        help="Port on which cchost will listen for node to node communication. By default, a random port is chosen.",
    )
    parser.add_argument(
        "--platform",
        default="virtual",
        choices=["sgx", "virtual"],
        help="Type of enclave used when starting cchost",
    )
    parser.add_argument(
        "--package",
        "-p",
        default="/tmp/scitt/lib/libscitt",
        help="The enclave package to load",
    )
    parser.add_argument(
        "--constitution-file",
        action="append",
        type=Path,
        help="Path to the initial constitution. May be specified multiple times",
        default=[],
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default="workspace",
        help="Path to a workspace directory",
    )
    parser.add_argument(
        "--enable-faketime",
        help="Enable faketime support. The `faketime` file in the workspace can be used to adjust the time as seen by cchost",
        action="store_true",
    )

    args = parser.parse_args()
    if args.workspace.exists():
        shutil.rmtree(args.workspace)
    args.workspace.mkdir()

    enclave_file = get_enclave_path(args.platform, args.package)
    binary = args.cchost or get_default_cchost_path(args.platform)
    with CCHost(
        binary,
        args.platform,
        enclave_file,
        workspace=args.workspace,
        constitution=args.constitution_file,
        rpc_port=args.port,
        node_port=args.node_port,
        enable_faketime=args.enable_faketime,
    ) as cchost:
        while True:
            signal.pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
