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
import sys
import threading
from pathlib import Path
from typing import List, Optional

import aiotools
from loguru import logger as LOG

from pyscitt import crypto, governance


class ShutdownRequestException(Exception):
    ...


class UnexpectedExitException(Exception):
    ...


LOG.level("FAIL", no=60, color="<red>")
LOG.level("FATAL", no=60, color="<red>")

# Python 3.11 would make this obsolete with 'except*'
def match_taskgroup_error(group: aiotools.TaskGroupError, expected: type):
    errors = group.__errors__
    if len(errors) == 1:
        if isinstance(errors[0], expected):
            return True
        elif isinstance(errors[0], aiotools.TaskGroupError):
            return match_taskgroup_error(errors[0], expected)

    return False


class CCHost:
    binary: str
    enclave_file: Path
    enclave_type: str
    workspace: Path
    constitution: Path

    # Port numbers which cchost will used to listen for incoming connections.
    # If 0, a random port number will be assigned by the OS.
    listen_rpc_port: int
    listen_node_port: int

    # The effective port number on which cchost is listening. This is equal to
    # listen_rpc_port, unless the latter was zero in which case this field
    # reflects the randomly assigned port number.
    #
    # This field is only available after the service has started.
    rpc_port: int

    # Cryptographic material of the member
    member_private_key: crypto.Pem
    member_cert: crypto.Pem
    encryption_private_key: crypto.Pem

    # Background thread on which an asyncio event loop runs
    thread: threading.Thread
    loop: asyncio.AbstractEventLoop

    # Events used to communicate from the main thread to the asyncio thread.
    # These must not be set directly from the main thread, but instead using
    # `loop.call_soon_threadsafe`
    shutdown_request: asyncio.Event

    # State used to communicate from the asyncio thread back to the main thread.
    # The condition variable is signaled whenever these change.
    cond: threading.Condition
    ready: bool  # True once the service is accepting connections
    thread_exception: Optional[BaseException]

    def __init__(
        self,
        binary: str,
        enclave_type: str,
        enclave_file: Path,
        workspace: Path,
        constitution: Path,
        rpc_port: int = 0,
        node_port: int = 0,
    ):
        self.binary = binary
        self.listen_rpc_port = rpc_port
        self.listen_node_port = node_port
        self.enclave_type = enclave_type
        self.enclave_file = enclave_file.absolute()
        self.workspace = workspace.absolute()
        self.constitution = constitution.absolute()

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

        self.thread = threading.Thread(target=self._execute)

        self.cond = threading.Condition()
        self.ready = False
        self.thread_exception = None

        self.loop = asyncio.new_event_loop()

        # Event objects must be created on the loop they will be accessed from.
        async def create_event():
            return asyncio.Event()

        self.shutdown_request = self.loop.run_until_complete(create_event())

    def __enter__(self):
        self.thread.start()

        try:
            with self.cond:
                while not self.ready and self.thread_exception is None:
                    self.cond.wait()

                if self.thread_exception is not None:
                    raise self.thread_exception

        except:
            # This is to handle the case where the wait is interrupted,
            # by a KeyboardInterrupt for example.
            self.loop.call_soon_threadsafe(self.shutdown_request.set)
            self.thread.join()
            raise

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.loop.call_soon_threadsafe(self.shutdown_request.set)
        finally:
            self.thread.join()

        if self.thread_exception is not None:
            raise self.thread_exception

    def _execute(self):
        """
        Entrypoint for the background thread.
        """
        try:
            self.loop.run_until_complete(self._start_service())
        except BaseException as e:
            with self.cond:
                self.thread_exception = e
                self.cond.notify_all()

    async def _start_service(self):
        """
        Run cchost in a loop, handling shutdown requests.
        """
        self._populate_workspace()

        try:
            await self._start_process()
        except aiotools.TaskGroupError as e:
            if match_taskgroup_error(e, ShutdownRequestException):
                return
            else:
                raise

    async def _start_process(self):
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
        )

        # We use two nested task groups. The reason for this is we want the log
        # processing tasks to keep running all the way until after the process
        # has exited.
        async with aiotools.TaskGroup() as tg_logs:
            tg_logs.create_task(self._process_stdout(process.stdout))
            tg_logs.create_task(self._process_stderr(process.stderr))

            try:
                async with aiotools.TaskGroup() as tg:
                    tg.create_task(self._wait_ready())

                    # This method will raise exceptions when requests come
                    # in from the main thread. The exceptions will cancel the
                    # other tasks and be handled by the caller.
                    tg.create_task(self._handle_shutdown(process))

                    await process.wait()
                    raise UnexpectedExitException()

            finally:
                # We want to kill the process whatever happens.
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
                    # This can happen if the process is already dead.
                    pass

    async def _handle_shutdown(self, process):
        await self.shutdown_request.wait()
        raise ShutdownRequestException()

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
                context = {"function": msg["file"], "line": msg["number"]}
                if "e_ts" in msg:
                    context["name"] = "enclave"
                else:
                    context["name"] = "host"
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
                with self.cond:
                    self.ready = True
                    self.cond.notify_all()
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

    def _populate_workspace(self):
        service_cert = self.workspace / "service_cert.pem"

        ENCLAVE_TYPES = {
            "virtual": "Virtual",
            "release": "Release",
        }

        config = {
            "enclave": {
                "file": str(self.enclave_file),
                "type": ENCLAVE_TYPES[self.enclave_type],
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
            "logging": {"format": "Json", "host_level": "Trace"},
            "output_files": {
                "rpc_addresses_file": str(self.workspace / "rpc_addresses.json"),
            },
            "command": {
                "type": "Start",
                "service_certificate_file": str(service_cert),
                "start": {
                    "constitution_files": [str(f) for f in self._constitution_files()],
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
            },
        }

        with open(self.workspace / "config.json", "w") as f:
            json.dump(config, f)

    def _constitution_files(self) -> List[Path]:
        return [
            self.constitution / "validate.js",
            self.constitution / "apply.js",
            self.constitution / "resolve.js",
            self.constitution / "actions.js",
            self.constitution / "scitt.js",
        ]


def get_enclave_path(enclave_type, enclave_package) -> Path:
    ENCLAVE_SUFFIX = {
        "virtual": "virtual.so",
        "release": "enclave.so.signed",
    }
    return Path(f"{enclave_package}.{ENCLAVE_SUFFIX[enclave_type]}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cchost", default="/opt/ccf/bin/cchost", help="Path to the cchost binary"
    )
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
        "--enclave-type",
        "-e",
        default="virtual",
        help="Type of enclave used when starting cchost",
    )
    parser.add_argument(
        "--package",
        "-p",
        default="/tmp/scitt/lib/libscitt",
        help="The enclave package to load",
    )
    parser.add_argument(
        "--constitution",
        type=Path,
        default="/tmp/scitt/share/scitt/constitution",
        help="Path to the directory containing the initial constitution",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default="workspace",
        help="Path to a workspace directory",
    )

    args = parser.parse_args()
    if args.workspace.exists():
        shutil.rmtree(args.workspace)
    args.workspace.mkdir()

    enclave_file = get_enclave_path(args.enclave_type, args.package)
    with CCHost(
        args.cchost,
        args.enclave_type,
        enclave_file,
        workspace=args.workspace,
        constitution=args.constitution,
        rpc_port=args.port,
        node_port=args.node_port,
    ) as cchost:
        while True:
            signal.pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
