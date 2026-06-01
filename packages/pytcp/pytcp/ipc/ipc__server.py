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
This module contains the IPC control-channel AF_UNIX server.

'IpcServer' is a 'Subsystem' that listens on an AF_UNIX stream socket and
serves each accepted client on its own dispatch thread: read a framed
request, route its op to a handler, write the framed response. It is the
daemon-side half of the boundary and — unlike the codec core — imports
the stack 'Subsystem' base, so it stays pytcp-resident (see
docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__server.py

ver 3.0.8
"""

import os
import socket
import threading
from collections.abc import Callable, Mapping
from typing import override

from pytcp.ipc.ipc__control import handle_control_call
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__errors import IpcFrameError, IpcMessageError
from pytcp.ipc.ipc__fdpass import send_frame_with_fd
from pytcp.ipc.ipc__frame import recv_frame, send_frame
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__socket_session import SocketSession
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem

# A handler takes the decoded request and returns the full response
# message, so it owns the response 'kind' (a control handler returns
# RESPONSE_OK or RESPONSE_ERROR depending on the call's outcome).
type IpcRequestHandler = Callable[[IpcMessage], IpcMessage]

IPC__SERVER__LISTEN_BACKLOG: int = 64
IPC__SERVER__CLIENT_JOIN_TIMEOUT__SEC: float = 2.0


def _handle_ping(request: IpcMessage, /) -> IpcMessage:
    """
    Handle a PING request — answer with a fixed 'PONG' body.
    """

    return IpcMessage(
        kind=IpcMessageKind.RESPONSE_OK,
        op=request.op,
        req_id=request.req_id,
        body=b"PONG",
    )


DEFAULT_HANDLERS: dict[int, IpcRequestHandler] = {
    IpcOp.PING: _handle_ping,
    IpcOp.CONTROL_CALL: handle_control_call,
}


class IpcServer(Subsystem):
    """
    The IPC control-channel AF_UNIX server.
    """

    _subsystem_name = "IPC Server"

    _socket_path: str
    _handlers: dict[int, IpcRequestHandler]
    _listen_socket: socket.socket
    _lock__clients: threading.Lock
    _client_sockets: list[socket.socket]
    _client_threads: list[threading.Thread]

    @override
    def __init__(
        self,
        *,
        socket_path: str,
        handlers: Mapping[int, IpcRequestHandler] | None = None,
    ) -> None:
        """
        Bind and listen on the AF_UNIX control socket.
        """

        self._socket_path = socket_path

        super().__init__(info=socket_path)

        self._handlers = dict(DEFAULT_HANDLERS) if handlers is None else dict(handlers)
        self._lock__clients = threading.Lock()
        self._client_sockets = []
        self._client_threads = []

        self._listen_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._unlink_socket_path()
        self._listen_socket.bind(socket_path)
        self._listen_socket.listen(IPC__SERVER__LISTEN_BACKLOG)
        # A short accept timeout lets '_subsystem_loop' return between
        # idle polls so the base loop can re-check the stop event.
        self._listen_socket.settimeout(SUBSYSTEM_SLEEP_TIME__SEC)

    @override
    def _subsystem_loop(self) -> None:
        """
        Accept one pending client connection and hand it to a dedicated
        dispatch thread. 'accept' raises 'TimeoutError' (an 'OSError'
        subclass) on the idle-poll timeout and 'OSError' once the listen
        socket is closed during teardown — both just take a fresh tick.
        """

        try:
            conn, _ = self._listen_socket.accept()
        except OSError:
            return

        conn.settimeout(None)
        thread = threading.Thread(
            target=self._serve_client,
            args=(conn,),
            name="IPC-Client",
        )
        with self._lock__clients:
            self._client_sockets.append(conn)
            self._client_threads.append(thread)
        thread.start()

    def _serve_client(self, conn: socket.socket, /) -> None:
        """
        Serve one client connection until it closes or the server stops:
        read a framed request, dispatch it, write the framed response.
        Each connection owns a 'SocketSession' (its open-socket table),
        reaped when the connection ends — the daemon's analogue of a
        kernel closing a process's fds on exit.
        """

        session = SocketSession(self._event__stop_subsystem)
        try:
            while not self._event__stop_subsystem.is_set():
                try:
                    payload = recv_frame(conn)
                except IpcFrameError, OSError:
                    break

                if payload is None:
                    break

                try:
                    request = IpcMessage.from_bytes(payload)
                except IpcMessageError:
                    # Structurally broken frame (bad kind / short
                    # header) — a protocol violation; drop the client.
                    break

                if request.op == IpcOp.SOCKET_CALL:
                    if not self._serve_socket_call(conn, session, request):
                        break
                    continue

                try:
                    send_frame(conn, self._dispatch(request).to_bytes())
                except OSError:
                    break
        finally:
            session.close_all()
            try:
                conn.close()
            except OSError:
                pass

    def _serve_socket_call(
        self,
        conn: socket.socket,
        session: SocketSession,
        request: IpcMessage,
        /,
    ) -> bool:
        """
        Serve one SOCKET_CALL on the connection's session and write the
        response, passing the data-channel fd when the call opened a
        socket. Return False (stop serving) on a write error.

        The passed client-end socket is closed once handed off — the
        client now owns the kernel object via SCM_RIGHTS, so the daemon
        drops its reference whether or not the send succeeded.
        """

        response, fd_socket = session.handle(request)
        try:
            if fd_socket is not None:
                send_frame_with_fd(conn, response.to_bytes(), fd_socket.fileno())
            else:
                send_frame(conn, response.to_bytes())
        except OSError:
            return False
        finally:
            if fd_socket is not None:
                try:
                    fd_socket.close()
                except OSError:
                    pass
        return True

    def _dispatch(self, request: IpcMessage, /) -> IpcMessage:
        """
        Route a request to its op handler and build the response.

        An op with no registered handler yields a RESPONSE_ERROR
        (ENOSYS-style) echoing the request's op and correlation id, so
        the client learns the op is unsupported rather than seeing the
        connection drop.
        """

        handler = self._handlers.get(request.op)

        if handler is None:
            return IpcMessage(
                kind=IpcMessageKind.RESPONSE_ERROR,
                op=request.op,
                req_id=request.req_id,
                body=f"unsupported op {request.op}".encode(),
            )

        return handler(request)

    @override
    def _stop(self) -> None:
        """
        Close the listen socket, tear down every client connection, join
        the dispatch threads, and unlink the AF_UNIX socket node. The
        base 'stop()' has already joined the accept worker before this
        runs, so the client lists are final and race-free.
        """

        try:
            self._listen_socket.close()
        except OSError:
            pass

        with self._lock__clients:
            sockets = list(self._client_sockets)
            threads = list(self._client_threads)

        for conn in sockets:
            # 'shutdown' (not just 'close') reliably interrupts a
            # dispatch thread blocked in 'recv_frame'; a bare 'close'
            # on Linux can leave the blocked syscall pending.
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        for thread in threads:
            thread.join(timeout=IPC__SERVER__CLIENT_JOIN_TIMEOUT__SEC)

        self._unlink_socket_path()

    def _unlink_socket_path(self) -> None:
        """
        Remove the AF_UNIX socket node if present (clears a stale node
        before bind and the live node after stop).
        """

        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass
