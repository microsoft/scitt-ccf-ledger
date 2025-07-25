# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import asyncio
from typing import Tuple

import aiotools
from loguru import logger as LOG

from .async_utils import EventLoopThread, race_tasks


class Proxy(EventLoopThread):
    """
    A TCP proxy, running as a context manager.

    The proxy listens for connections on a socket, and for each incoming
    connection creates a new outgoing connection to a pre-configured upstream
    host and port number. It then forwards data back and forth between the two
    sockets.

    The configured upstream can be modified after instantiation by calling
    `set_upstream`. The change only affects future connections, not existing
    established ones. In our use case, the previous upstream service is shut
    down, which closes these established connectionsa anyway.

    This is used to provide a stable hostname and port number for tests to use,
    even as the cchost process is restarted and assigned a different port number.
    """

    # Keeping this as a tuple instead of two variables makes assignments atomic.
    upstream: Tuple[str, int]

    # Port on which the proxy is listening. This will be randomly assigned by
    # the operating system when the proxy starts.
    port: int

    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        super().__init__()
        self.upstream = (upstream_host, upstream_port)

    def set_upstream(self, upstream_host: str, upstream_port: int) -> None:
        """Change the host and port number the proxy connect to."""
        LOG.debug(f"Changing upstream to {upstream_host}:{upstream_port}")
        self.upstream = (upstream_host, upstream_port)

    async def run(self) -> None:
        """Invoked by EventLoopThread when the Proxy is started."""
        self.server = None
        self.stop_request = asyncio.Event()
        try:
            async with aiotools.TaskGroup() as tg:
                self.server = await asyncio.start_server(
                    lambda reader, writer: tg.create_task(
                        self._handle_connection(reader, writer)
                    ),
                    "127.0.0.1",
                )

                self.port = self.server.sockets[0].getsockname()[1]
                LOG.debug(f"Proxy is listening on port {self.port}")

                self.set_ready()
                await self.server.start_serving()
                await self.stop_request.wait()
                self.stop_request.clear()

        except asyncio.CancelledError:
            LOG.debug("Proxy server cancelled, shutting down gracefully")
            raise
        finally:
            if self.server:
                self.server.close()
                await self.server.wait_closed()
                LOG.debug("Proxy server closed")

    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        try:
            (host, port) = self.upstream
            LOG.debug(f"Connecting to upstream at {host}:{port}")
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
            try:
                # race_tasks is used to stop as soon as either connection has been closed.
                await race_tasks(
                    self._pipe(upstream_reader, client_writer),
                    self._pipe(client_reader, upstream_writer),
                )
            finally:
                upstream_writer.close()
                await upstream_writer.wait_closed()
        finally:
            client_writer.close()
            await client_writer.wait_closed()

    async def _pipe(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Copy data from a reader to a writer.

        Returns when the reader has reached EOF.
        """
        while True:
            data = await reader.read(1024)
            if not data:
                break
            writer.write(data)

    def __exit__(self, exc_type, exc_val, exc_tb):
        LOG.info("Exiting Proxy context manager, terminating proxy process")
        if self.stop_request:
            LOG.debug("Triggering shutdown request") 
            self.stop_request.set()
        return super().__exit__(exc_type, exc_val, exc_tb)
