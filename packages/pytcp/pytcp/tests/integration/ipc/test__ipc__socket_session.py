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
Integration tests for the daemon-side per-client socket session.

These drive the SOCKET_CALL op directly over a raw 'IpcClient' against a
live 'IpcServer' (the 'IpcControlTestCase' harness), exercising the
daemon's handle table, the SCM_RIGHTS data-channel handoff, the
handle-keyed control methods, and the client-disconnect reap — without
the higher-level 'ClientTcpSocket' (which lands separately).

pytcp/tests/integration/ipc/test__ipc__socket_session.py

ver 3.0.10
"""

import socket

from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__socket_rpc import decode_socket_value, encode_socket_request
from pytcp.runtime.socket import SO_KEEPALIVE, SOL_SOCKET, AddressFamily, SocketType
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcSocketSession(IpcControlTestCase):
    """
    The daemon-side per-client socket-session integration tests.
    """

    def _raw_client(self) -> IpcClient:
        """
        Open a raw IPC client against the server and register its close.
        """

        client = IpcClient(socket_path=self._socket_path)
        self.addCleanup(client.close)
        return client

    def _open(
        self,
        client: IpcClient,
        /,
        *,
        family: AddressFamily = AddressFamily.INET4,
        socket_type: SocketType = SocketType.STREAM,
    ) -> tuple[IpcMessage, int | None]:
        """
        Issue the fd-bearing 'socket' SOCKET_CALL and return the response
        and its passed data-channel fd.
        """

        return client.request_with_fd(
            IpcOp.SOCKET_CALL,
            body=encode_socket_request(
                method="socket",
                handle=None,
                args={"family": family, "type": socket_type},
            ),
        )

    def _call(
        self,
        client: IpcClient,
        /,
        *,
        method: str,
        handle: int | None,
        args: dict[str, object],
    ) -> IpcMessage:
        """
        Issue a plain (non-fd) handle-keyed SOCKET_CALL and return the
        response message.
        """

        return client.request(
            IpcOp.SOCKET_CALL,
            body=encode_socket_request(method=method, handle=handle, args=args),
        )

    def test__ipc__socket__open_returns_handle_and_fd(self) -> None:
        """
        Ensure the 'socket' call returns an integer handle and passes a
        working data-channel descriptor, so the client gets a real fd
        for the new socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._raw_client()
        response, fd = self._open(client)
        self.assertIsNotNone(fd, msg="The 'socket' call must pass a data-channel fd.")
        assert fd is not None
        data_end = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd)
        self.addCleanup(data_end.close)

        self.assertEqual(
            (response.kind, decode_socket_value(response.body), data_end.family),
            (IpcMessageKind.RESPONSE_OK, {"handle": 0}, socket.AF_UNIX),
            msg="The 'socket' call must return handle 0 with a working AF_UNIX data-channel fd.",
        )

    def test__ipc__socket__dgram_open_returns_dgram_fd(self) -> None:
        """
        Ensure a DGRAM 'socket' call returns a handle and passes a
        working SOCK_DGRAM data-channel descriptor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._raw_client()
        response, fd = self._open(client, socket_type=SocketType.DGRAM)
        self.assertIsNotNone(fd, msg="The DGRAM 'socket' call must pass a data-channel fd.")
        assert fd is not None
        data_end = socket.socket(fileno=fd)
        self.addCleanup(data_end.close)

        self.assertEqual(
            (response.kind, decode_socket_value(response.body), data_end.type),
            (IpcMessageKind.RESPONSE_OK, {"handle": 0}, socket.SOCK_DGRAM),
            msg="A DGRAM socket() must return handle 0 with a working SOCK_DGRAM data-channel fd.",
        )

    def test__ipc__socket__dgram_bind_then_getsockname(self) -> None:
        """
        Ensure a bind on a DGRAM handle is reflected by a subsequent
        getsockname over the same handle.

        Reference: RFC 768 (UDP — local socket addressing).
        """

        client = self._raw_client()
        _, fd = self._open(client, socket_type=SocketType.DGRAM)
        assert fd is not None
        self.addCleanup(socket.socket(fileno=fd).close)

        self._call(client, method="bind", handle=0, args={"address": ("0.0.0.0", 41001)})
        response = self._call(client, method="getsockname", handle=0, args={})

        self.assertEqual(
            decode_socket_value(response.body),
            ("0.0.0.0", 41001),
            msg="getsockname must reflect the address bound on a DGRAM handle.",
        )

    def test__ipc__socket__bind_then_getsockname(self) -> None:
        """
        Ensure a bind on a handle is reflected by a subsequent
        getsockname over the same handle.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        client = self._raw_client()
        _, fd = self._open(client)
        assert fd is not None
        self.addCleanup(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd).close)

        self._call(client, method="bind", handle=0, args={"address": ("0.0.0.0", 40001)})
        response = self._call(client, method="getsockname", handle=0, args={})

        self.assertEqual(
            decode_socket_value(response.body),
            ("0.0.0.0", 40001),
            msg="getsockname must reflect the address bound over the same handle.",
        )

    def test__ipc__socket__setsockopt_getsockopt_round_trip(self) -> None:
        """
        Ensure a setsockopt on a handle is observable via getsockopt over
        the same handle.

        Reference: RFC 1122 §4.2.3.6 (TCP keep-alive SO_KEEPALIVE).
        """

        client = self._raw_client()
        _, fd = self._open(client)
        assert fd is not None
        self.addCleanup(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd).close)

        self._call(
            client, method="setsockopt", handle=0, args={"level": SOL_SOCKET, "optname": SO_KEEPALIVE, "value": 1}
        )
        response = self._call(
            client, method="getsockopt", handle=0, args={"level": SOL_SOCKET, "optname": SO_KEEPALIVE}
        )

        self.assertEqual(
            decode_socket_value(response.body),
            1,
            msg="getsockopt must read back the value set by setsockopt over the same handle.",
        )

    def test__ipc__socket__unknown_handle_errors(self) -> None:
        """
        Ensure a handle-keyed call against an unallocated handle returns
        a RESPONSE_ERROR rather than acting on an unrelated socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._raw_client()
        response = self._call(client, method="getsockname", handle=999, args={})

        self.assertEqual(
            response.kind,
            IpcMessageKind.RESPONSE_ERROR,
            msg="A call against an unknown handle must return a RESPONSE_ERROR.",
        )

    def test__ipc__socket__close_releases_handle(self) -> None:
        """
        Ensure closing a handle frees it, so a later call against the
        same handle errors.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._raw_client()
        _, fd = self._open(client)
        assert fd is not None
        data_end = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd)
        self.addCleanup(data_end.close)

        close_response = self._call(client, method="close", handle=0, args={})
        reuse_response = self._call(client, method="getsockname", handle=0, args={})

        self.assertEqual(
            (close_response.kind, reuse_response.kind),
            (IpcMessageKind.RESPONSE_OK, IpcMessageKind.RESPONSE_ERROR),
            msg="close must succeed and release the handle so a later call against it errors.",
        )

    def test__ipc__socket__disconnect_reaps_open_sockets(self) -> None:
        """
        Ensure a client disconnect reaps its still-open sockets: the
        daemon-side bridge end closes, surfacing as EOF on the client's
        retained data-channel fd.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._raw_client()
        _, fd = self._open(client)
        assert fd is not None
        data_end = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd)
        data_end.settimeout(5.0)
        self.addCleanup(data_end.close)

        client.close()

        self.assertEqual(
            data_end.recv(8),
            b"",
            msg="Disconnect must reap the socket, closing the daemon bridge end (EOF on the client fd).",
        )
