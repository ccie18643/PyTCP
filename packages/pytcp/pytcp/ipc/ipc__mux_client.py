################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the multiplexed IPC client connector.

'MuxIpcClient' owns a single AF_UNIX stream connection to the daemon and
lets many concurrent callers issue request/response calls over it. A
background reader thread receives every response (capturing any
SCM_RIGHTS descriptor) and routes it to the matching caller by 'req_id',
so out-of-order replies, fd-bearing replies, and fire-and-forget
('call_async') calls all work over one socket. It sits beside the simple
synchronous 'IpcClient' (which the coarse control-plane proxies keep) and
is the basis for the daemon-backed socket drop-in's non-blocking calls.
It is part of the extraction-ready codec core — net_proto + stdlib only,
no pytcp stack reach-in (see docs/refactor/kernel_userspace_separation.md
§2).

pytcp/ipc/ipc__mux_client.py

ver 3.0.8
"""

import os
import socket
import threading
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final, Self

from net_proto.lib.buffer import Buffer
from pytcp.ipc.ipc__client import (
    IPC__CLIENT__DEFAULT_TIMEOUT__SEC,
    IPC__CLIENT__REQ_ID_MASK,
)
from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__errors import IpcConnectionError, IpcError, IpcMessageError
from pytcp.ipc.ipc__fdpass import recv_frame_with_fd
from pytcp.ipc.ipc__frame import send_frame
from pytcp.ipc.ipc__message import IpcMessage


class _DefaultTimeout:
    """
    The 'use the client's configured default timeout' sentinel type.
    """


_USE_DEFAULT_TIMEOUT: Final[_DefaultTimeout] = _DefaultTimeout()


@dataclass(kw_only=True, slots=True)
class PendingCall:
    """
    A registered-but-unresolved multiplexed call awaiting its response.
    """

    req_id: int
    op: int
    event: threading.Event = field(default_factory=threading.Event)
    message: IpcMessage | None = field(default=None)
    fd: int | None = field(default=None)
    error: BaseException | None = field(default=None)


class MuxIpcClient:
    """
    A multiplexed IPC client routing concurrent calls over one socket.
    """

    def __init__(
        self,
        *,
        socket_path: str,
        timeout: float = IPC__CLIENT__DEFAULT_TIMEOUT__SEC,
    ) -> None:
        """
        Open an AF_UNIX connection and start the background reader thread.
        """

        self._timeout = timeout
        self._write_lock = threading.Lock()
        self._registry_lock = threading.Lock()
        self._next_req_id = 0
        self._pending: dict[int, PendingCall] = {}
        self._closed = False

        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        try:
            self._socket.connect(socket_path)
        except OSError:
            # Close the just-created socket so a failed connect (e.g. the
            # daemon not up yet) does not orphan an open descriptor.
            self._socket.close()
            raise
        # Drop the timeout so the reader thread blocks on recv until a
        # response arrives or the connection is shut down.
        self._socket.settimeout(None)

        self._reader = threading.Thread(
            target=self._reader_loop,
            name="pytcp-ipc-mux-reader",
            daemon=True,
        )
        self._reader.start()

    def call_async(self, op: int, /, *, body: Buffer = b"") -> PendingCall:
        """
        Register a call and send its request without waiting for a reply.

        Returns the pending handle; resolve it later with 'wait'. This is
        the basis for non-blocking ('EINPROGRESS') connect.
        """

        return self._register_and_send(op, body)

    def call(
        self,
        op: int,
        /,
        *,
        body: Buffer = b"",
        timeout: float | None | _DefaultTimeout = _USE_DEFAULT_TIMEOUT,
    ) -> tuple[IpcMessage, int | None]:
        """
        Send a request and block for its correlated response.

        Returns the response message and any descriptor passed alongside
        it (the data-channel end for a newly opened socket), or None when
        the response carried no descriptor. A 'timeout' of None waits
        without bound (used by blocking 'accept').
        """

        return self.wait(self._register_and_send(op, body), timeout=timeout)

    def wait(
        self,
        pending: PendingCall,
        /,
        *,
        timeout: float | None | _DefaultTimeout = _USE_DEFAULT_TIMEOUT,
    ) -> tuple[IpcMessage, int | None]:
        """
        Block until 'pending' resolves and return its response and fd.

        Raises 'TimeoutError' if the deadline elapses first and
        'IpcConnectionError' if the connection died before a reply.
        """

        effective = self._timeout if isinstance(timeout, _DefaultTimeout) else timeout

        if not pending.event.wait(effective):
            with self._registry_lock:
                self._pending.pop(pending.req_id, None)
            # The reader may have delivered between the wait expiring and
            # the pop above; reclaim any descriptor it stored so it does
            # not leak now that no caller will consume it.
            if pending.fd is not None:
                os.close(pending.fd)
                pending.fd = None
            raise TimeoutError(f"IPC call (op={pending.op}) timed out after {effective} s.")

        with self._registry_lock:
            self._pending.pop(pending.req_id, None)

        if pending.error is not None:
            raise pending.error

        assert pending.message is not None  # event set without error => message present
        return pending.message, pending.fd

    def cancel(self, req_id: int, /) -> None:
        """
        Drop a pending call so a later reply for it is ignored.

        Any descriptor already delivered for the call is closed so it does
        not leak.
        """

        with self._registry_lock:
            pending = self._pending.pop(req_id, None)

        if pending is not None and pending.fd is not None:
            os.close(pending.fd)
            pending.fd = None

    def close(self) -> None:
        """
        Close the connection, stop the reader, and fail any pending calls.
        """

        with self._write_lock:
            if self._closed:
                return
            self._closed = True

        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        self._reader.join(timeout=self._timeout)

        try:
            self._socket.close()
        except OSError:
            pass

        self._fail_all(IpcConnectionError("Multiplexed IPC client was closed."))

    def _register_and_send(self, op: int, body: Buffer, /) -> PendingCall:
        """
        Allocate a req_id, register the pending call, and send its request.
        """

        with self._write_lock:
            if self._closed:
                raise IpcConnectionError("Multiplexed IPC client is closed.")

            req_id = self._next_req_id
            self._next_req_id = (self._next_req_id + 1) & IPC__CLIENT__REQ_ID_MASK

            pending = PendingCall(req_id=req_id, op=op)
            with self._registry_lock:
                self._pending[req_id] = pending

            request = IpcMessage(
                kind=IpcMessageKind.REQUEST,
                op=op,
                req_id=req_id,
                body=bytes(body),
            )

            try:
                send_frame(self._socket, request.to_bytes())
            except OSError as error:
                with self._registry_lock:
                    self._pending.pop(req_id, None)
                raise IpcConnectionError(
                    "Failed to send a request over the daemon connection.",
                ) from error

            return pending

    def _reader_loop(self) -> None:
        """
        Receive responses and route each to its matching pending call.
        """

        try:
            while True:
                try:
                    payload, fd = recv_frame_with_fd(self._socket)
                except OSError, IpcError:
                    # OSError covers a shut-down / reset socket; the codec
                    # raises IpcFrameError (an IpcError) on a clean EOF or a
                    # truncated / oversize frame — either ends the stream.
                    break

                try:
                    message = IpcMessage.from_bytes(payload)
                except IpcMessageError:
                    if fd is not None:
                        os.close(fd)
                    break

                self._deliver(message, fd)
        finally:
            self._fail_all(
                IpcConnectionError("Daemon closed the control connection."),
            )

    def _deliver(self, message: IpcMessage, fd: int | None, /) -> None:
        """
        Hand a received response (and fd) to the matching pending call.
        """

        with self._registry_lock:
            pending = self._pending.get(message.req_id)
            if pending is not None:
                pending.message = message
                pending.fd = fd
                pending.event.set()
                fd = None  # Ownership transferred to the pending call.

        if fd is not None:
            # No matching caller (cancelled or unknown req_id) — do not
            # leak the descriptor.
            os.close(fd)

    def _fail_all(self, error: BaseException, /) -> None:
        """
        Fail every still-pending call and reclaim any delivered fds.
        """

        with self._registry_lock:
            pendings = list(self._pending.values())
            self._pending.clear()

        for pending in pendings:
            if pending.fd is not None:
                try:
                    os.close(pending.fd)
                except OSError:
                    pass
                pending.fd = None
            if pending.message is None and pending.error is None:
                pending.error = error
            pending.event.set()

    def __enter__(self) -> Self:
        """
        Enter the client context, returning the connected client.
        """

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Close the connection on context exit.
        """

        self.close()
