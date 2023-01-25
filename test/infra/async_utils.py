# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import asyncio
import threading
from abc import ABC, abstractmethod
from typing import Any, Awaitable, List, Optional

import aiotools


async def race_tasks(*awaitables: Awaitable[Any]):
    """
    Run a collection of awaitable objects as tasks, concurrently, until at least one
    of them completes or terminates with an exception. All uncompleted tasks
    will then be cancelled.

    If one or more tasks raise an error other than `asyncio.CancelledError`, a
    TaskGroupError containing all of them is raised.
    """
    async with aiotools.TaskGroup() as tg:
        tasks = [tg.create_task(a) for a in awaitables]
        (done, pending) = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()


class EventLoopThread(ABC):
    """
    Run an asyncio event loop in a background thread, whose lifetime is
    managed as a context manager.

    Subclasses of EventLoopThread should override the async `run` function.
    Instances of this class are used as a context manager, as part of a `with`
    block.

    When the context manager is entered, an asyncio event loop is created on a
    new background thread, and is used to execute the `run` function as a new
    task. The main thread, which created and entered this context manager, will
    block until the `run` implementation calls `set_ready`.

    When the context manager is exited, the task that was started sent a cancel
    request. It may still perform any necessary cleanup before exiting. The
    main thread will block until the task has exited.

    Unhandled exceptions that happen in the `run` function will be re-raised on
    the main thread, at the first opportunity. This may be while entering the
    context manager, if an exception is raised during startup, or when exiting
    it if the exception is raised later.
    """

    # Background thread on which the asyncio event loop runs
    _loop: asyncio.AbstractEventLoop
    _thread: threading.Thread

    # State used to communicate from the asyncio thread back to the main thread.
    # The condition variable is signaled whenever these change.
    _cond: threading.Condition
    _ready: bool
    _exception: Optional[BaseException]

    # Event used to communicate from the main thread to the asyncio thread.
    # This must not be set directly from the main thread, but instead using
    # `loop.call_soon_threadsafe`
    _shutdown_request: asyncio.Event

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._execute)
        self._cond = threading.Condition()
        self._ready = False
        self._exception = None
        self._shutdown_request = self._create_event()

    def _create_event(self) -> asyncio.Event:
        """
        Create an asyncio.Event instance on the event loop.

        This may be used in subclass' constructors to create new ways for the
        main thread to interact with the event loop. The events may then be
        set using the `_set_event` method.
        """

        async def f():
            return asyncio.Event()

        return self._loop.run_until_complete(f())

    def _set_event(self, event: asyncio.Event) -> None:
        """
        Call the `set` method on an Event instance that was created with `_create_event`.
        """
        self._loop.call_soon_threadsafe(event.set)

    def __enter__(self) -> "EventLoopThread":
        self._thread.start()

        try:
            self.wait_ready()
        except:
            # This is to handle the case where the wait_ready call is
            # interrupted, by a KeyboardInterrupt for example.
            self._set_event(self._shutdown_request)
            self._thread.join()
            raise

        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._set_event(self._shutdown_request)
        self._thread.join()

        if self._exception is not None:
            raise self._exception

    def _execute(self) -> None:
        try:
            task = race_tasks(self._shutdown_request.wait(), self.run())
            self._loop.run_until_complete(task)

        except BaseException as e:
            # This function runs as the entry-point of thread. Any exception
            # that bubbles out of it would be lost, so we catch everything and
            # keep it for the main thread to pick up.
            with self._cond:
                self._exception = e
                self._cond.notify_all()

    @abstractmethod
    async def run(self) -> None:
        raise NotImplementedError()

    def set_ready(self) -> None:
        """
        This method should be called by implementations of `run()` when they
        are in a "ready" state. Only after this method is called will the main
        thread that created this object return.

        After the ready flag was set once, it may be reused again and again.
        The main thread should issue a request through some other
        synchronization mean and block by calling `wait_ready`. After receiving
        and processing the request, the event loop thread can unblock the main
        thread by calling `set_ready` again.
        """
        with self._cond:
            self._ready = True
            self._cond.notify_all()

    def wait_ready(self) -> None:
        """
        Wait until the event loop thread either calls `set_ready` or terminates
        abnormally.
        """
        with self._cond:
            while not self._ready:
                if self._exception is not None:
                    raise self._exception

                self._cond.wait()

            # Clear the flag, so it can be re-used by subclasses.
            self._ready = False
