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
This module contains tests for the multiplexed IPC client.

pytcp/tests/unit/ipc/test__ipc__mux_client.py

ver 3.0.10
"""

import os
import shutil
import socket
import tempfile
import threading
from pathlib import Path
from typing import override
from unittest import TestCase

from pytcp.ipc.ipc__client import IPC__CLIENT__REQ_ID_MASK
from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__errors import IpcConnectionError
from pytcp.ipc.ipc__fdpass import send_frame_with_fd
from pytcp.ipc.ipc__frame import recv_frame, send_frame
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__mux_client import MuxIpcClient


class _FakeDaemon:
    """
    A minimal AF_UNIX listener standing in for the daemon control socket.
    """

    def __init__(self, socket_path: str, /) -> None:
        """
        Bind and listen on the given path and start accepting one client.
        """

        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(socket_path)
        self._listener.listen(1)
        self._conn: socket.socket | None = None
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    def _accept(self) -> None:
        """
        Accept the single inbound client connection.
        """

        conn, _ = self._listener.accept()
        self._conn = conn

    def wait_connected(self) -> None:
        """
        Block until the client has connected.
        """

        self._accept_thread.join(timeout=2.0)
        assert self._conn is not None, "fake daemon never accepted a connection"

    def recv_request(self) -> IpcMessage:
        """
        Read one request frame from the connected client.
        """

        assert self._conn is not None
        payload = recv_frame(self._conn)
        assert payload is not None, "client closed before sending a request"
        return IpcMessage.from_bytes(payload)

    def send_response(
        self,
        request: IpcMessage,
        /,
        *,
        body: bytes = b"",
        fd: int | None = None,
        kind: IpcMessageKind = IpcMessageKind.RESPONSE_OK,
    ) -> None:
        """
        Send a response correlated to the given request's 'req_id'.
        """

        assert self._conn is not None
        message = IpcMessage(kind=kind, op=request.op, req_id=request.req_id, body=body)
        if fd is None:
            send_frame(self._conn, message.to_bytes())
        else:
            send_frame_with_fd(self._conn, message.to_bytes(), fd)

    def drop_connection(self) -> None:
        """
        Close the accepted client connection (simulate daemon death).
        """

        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def close(self) -> None:
        """
        Close the listener and any accepted connection.
        """

        self.drop_connection()
        self._listener.close()


class TestMuxIpcClient(TestCase):
    """
    The multiplexed IPC client tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake daemon listener and a connected mux client.
        """

        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir, ignore_errors=True)
        self._socket_path = str(Path(self._tmpdir) / "pytcp.sock")
        self._daemon = _FakeDaemon(self._socket_path)
        self.addCleanup(self._daemon.close)
        self._client = MuxIpcClient(socket_path=self._socket_path)
        self.addCleanup(self._client.close)
        self._daemon.wait_connected()

    def test__ipc__mux_client__out_of_order_replies_correlate_by_req_id(self) -> None:
        """
        Ensure two concurrent calls each receive their own response even
        when the daemon replies in the opposite order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pending_a = self._client.call_async(1, body=b"AAA")
        pending_b = self._client.call_async(1, body=b"BBB")

        request_a = self._daemon.recv_request()
        request_b = self._daemon.recv_request()

        self.assertNotEqual(
            request_a.req_id,
            request_b.req_id,
            msg="Each call must allocate a distinct req_id.",
        )

        # Reply in reverse order.
        self._daemon.send_response(request_b, body=b"reply-B")
        self._daemon.send_response(request_a, body=b"reply-A")

        message_a, _ = self._client.wait(pending_a, timeout=2.0)
        message_b, _ = self._client.wait(pending_b, timeout=2.0)

        self.assertEqual(
            (message_a.body, message_b.body),
            (b"reply-A", b"reply-B"),
            msg="Each caller must receive the response correlated to its own req_id.",
        )

    def test__ipc__mux_client__fd_bearing_reply_reaches_caller(self) -> None:
        """
        Ensure a response carrying an SCM_RIGHTS descriptor delivers that
        descriptor to the matching caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        passed_a, passed_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(passed_a.close)
        self.addCleanup(passed_b.close)

        pending = self._client.call_async(2)
        request = self._daemon.recv_request()
        self._daemon.send_response(request, body=b"with-fd", fd=passed_a.fileno())

        message, received_fd = self._client.wait(pending, timeout=2.0)
        self.assertIsNotNone(
            received_fd,
            msg="An fd-bearing response must deliver a descriptor to the caller.",
        )
        assert received_fd is not None
        self.addCleanup(lambda: os.close(received_fd))

        # The received fd refers to the same pipe end: a write on it is
        # readable from the other socketpair end.
        os.write(received_fd, b"ping")
        self.assertEqual(
            passed_b.recv(4),
            b"ping",
            msg="The received descriptor must refer to the passed socket end.",
        )
        self.assertEqual(
            message.body,
            b"with-fd",
            msg="The fd-bearing response body must reach the caller intact.",
        )

    def test__ipc__mux_client__call_async_returns_before_reply(self) -> None:
        """
        Ensure 'call_async' registers and sends without blocking for the
        response — the pending handle is returned while the reply is still
        outstanding.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pending = self._client.call_async(3, body=b"x")

        self.assertEqual(
            pending.op,
            3,
            msg="The pending handle must record the requested op.",
        )
        self.assertEqual(
            pending.req_id & IPC__CLIENT__REQ_ID_MASK,
            pending.req_id,
            msg="The pending req_id must fit the 32-bit req_id space.",
        )

        # The daemon has not replied yet; the request is readable on its end.
        request = self._daemon.recv_request()
        self.assertEqual(
            request.req_id,
            pending.req_id,
            msg="The sent request must carry the pending handle's req_id.",
        )
        self._daemon.send_response(request, body=b"done")
        message, _ = self._client.wait(pending, timeout=2.0)
        self.assertEqual(
            message.body,
            b"done",
            msg="The reply must resolve the previously-returned pending handle.",
        )

    def test__ipc__mux_client__call_is_synchronous_round_trip(self) -> None:
        """
        Ensure the synchronous 'call' helper sends a request and returns
        the correlated response in one step.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        responder = threading.Thread(
            target=lambda: self._daemon.send_response(self._daemon.recv_request(), body=b"pong"),
            daemon=True,
        )
        responder.start()

        message, received_fd = self._client.call(7, body=b"ping", timeout=2.0)
        responder.join(timeout=2.0)

        self.assertEqual(
            message.body,
            b"pong",
            msg="The synchronous call must return the correlated response body.",
        )
        self.assertIsNone(
            received_fd,
            msg="An fd-less response must return None for the descriptor.",
        )

    def test__ipc__mux_client__wait_timeout_raises_timeout_error(self) -> None:
        """
        Ensure waiting on a call the daemon never answers raises
        'TimeoutError' once the wait deadline elapses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pending = self._client.call_async(4)
        self._daemon.recv_request()  # consume the request, never reply

        with self.assertRaises(TimeoutError):
            self._client.wait(pending, timeout=0.05)

    def test__ipc__mux_client__close_fails_outstanding_calls(self) -> None:
        """
        Ensure closing the client fails every outstanding call with an
        'IpcConnectionError' rather than hanging.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pending = self._client.call_async(5)
        self._daemon.recv_request()  # consume; do not reply

        self._client.close()

        with self.assertRaises(IpcConnectionError):
            self._client.wait(pending, timeout=2.0)

    def test__ipc__mux_client__reader_death_fails_outstanding_calls(self) -> None:
        """
        Ensure the daemon dropping the connection fails outstanding calls
        with an 'IpcConnectionError' instead of hanging the caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pending = self._client.call_async(6)
        self._daemon.recv_request()  # consume; do not reply
        self._daemon.drop_connection()

        with self.assertRaises(IpcConnectionError):
            self._client.wait(pending, timeout=2.0)

    def test__ipc__mux_client__cancel_drops_pending_and_ignores_late_reply(self) -> None:
        """
        Ensure a cancelled call is removed from the registry so a late
        reply for it is dropped while a sibling call still resolves.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pending_keep = self._client.call_async(8, body=b"keep")
        pending_drop = self._client.call_async(8, body=b"drop")

        request_keep = self._daemon.recv_request()
        request_drop = self._daemon.recv_request()
        # Identify which request belongs to which pending by req_id.
        if request_keep.req_id == pending_drop.req_id:
            request_keep, request_drop = request_drop, request_keep

        self._client.cancel(pending_drop.req_id)

        # Both get replies; the cancelled one must be silently dropped.
        self._daemon.send_response(request_drop, body=b"late-drop")
        self._daemon.send_response(request_keep, body=b"kept")

        message_keep, _ = self._client.wait(pending_keep, timeout=2.0)
        self.assertEqual(
            message_keep.body,
            b"kept",
            msg="The non-cancelled call must still resolve after a sibling cancel.",
        )

    def test__ipc__mux_client__context_manager_closes_on_exit(self) -> None:
        """
        Ensure the client closes its connection when used as a context
        manager.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        second_daemon_path = str(Path(self._tmpdir) / "pytcp2.sock")
        daemon = _FakeDaemon(second_daemon_path)
        self.addCleanup(daemon.close)

        with MuxIpcClient(socket_path=second_daemon_path) as client:
            daemon.wait_connected()
            pending = client.call_async(9)
            request = daemon.recv_request()
            daemon.send_response(request, body=b"ok")
            message, _ = client.wait(pending, timeout=2.0)
            self.assertEqual(
                message.body,
                b"ok",
                msg="The client must round-trip while the context is open.",
            )

        with self.assertRaises(IpcConnectionError):
            client.call_async(10)
