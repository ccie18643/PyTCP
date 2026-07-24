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
Tests for the IPC socket-syscall RPC body codec.

pytcp/tests/unit/ipc/test__ipc__socket_rpc.py

ver 3.0.9
"""

import os
from unittest import TestCase
from unittest.mock import create_autospec

from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__errors import IpcConnectionError, IpcRemoteError
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__socket_rpc import (
    SocketRequest,
    accept_socket,
    decode_socket_request,
    decode_socket_value,
    encode_socket_error,
    encode_socket_ok,
    encode_socket_request,
    raise_socket_error,
)
from pytcp.runtime.socket import AddressFamily


class TestIpcSocketRpc(TestCase):
    """
    The IPC socket-syscall RPC body codec tests.
    """

    def test__ipc__socket_rpc__request_round_trip(self) -> None:
        """
        Ensure a socket request round-trips its method, handle, and
        typed keyword arguments through the JSON body codec.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for request in [
            SocketRequest(method="socket", handle=None, args={"family": AddressFamily.INET4}),
            SocketRequest(method="connect", handle=3, args={"address": ("10.0.1.7", 80)}),
            SocketRequest(method="setsockopt", handle=3, args={"level": 6, "optname": 1, "value": b"\x01"}),
            SocketRequest(method="close", handle=3, args={}),
        ]:
            with self.subTest(request=request):
                self.assertEqual(
                    decode_socket_request(
                        encode_socket_request(
                            method=request.method,
                            handle=request.handle,
                            args=request.args,
                        )
                    ),
                    request,
                    msg=f"Socket request {request!r} must round-trip field-by-field.",
                )

    def test__ipc__socket_rpc__ok_round_trip(self) -> None:
        """
        Ensure a successful result round-trips through the OK body
        codec, including a typed (bytes) return value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [{"handle": 0}, ("10.0.1.7", 80), b"\x00\x01", None]:
            with self.subTest(value=value):
                self.assertEqual(
                    decode_socket_value(encode_socket_ok(value)),
                    value,
                    msg=f"Socket OK value {value!r} must round-trip through the body codec.",
                )

    def test__ipc__socket_rpc__error_raises_remote(self) -> None:
        """
        Ensure an error body decodes into an 'IpcRemoteError' carrying
        the remote exception's type name and message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_socket_error(error_type="ConnectionRefusedError", message="Connection refused")

        with self.assertRaises(IpcRemoteError) as error:
            raise_socket_error(body)

        self.assertEqual(
            (error.exception.error_type, error.exception.remote_message),
            ("ConnectionRefusedError", "Connection refused"),
            msg="A socket error body must surface as an IpcRemoteError with the remote type and message.",
        )


class TestIpcSocketRpc__AcceptDecode(TestCase):
    """
    The fd-bearing 'accept' client-RPC decode paths, exercising the
    response-kind dispatch, the data-channel descriptor handling, and
    the (handle, peer host, peer port) tuple decode — none of which the
    codec-only round-trip tests reach.
    """

    def test__accept__ok_returns_handle_peer_and_fd(self) -> None:
        """
        Ensure a RESPONSE_OK accept returns (child_handle, (host, port),
        data_fd) with the peer host at index 0 and port at index 1.

        Reference: RFC 9293 §3.5 (passive open / accept).
        """

        read_fd, write_fd = os.pipe()
        self.addCleanup(lambda: os.close(write_fd))
        client = create_autospec(IpcClient, spec_set=True)
        client.request_with_fd.return_value = (
            IpcMessage(
                kind=IpcMessageKind.RESPONSE_OK,
                op=IpcOp.SOCKET_CALL,
                req_id=1,
                body=encode_socket_ok({"handle": 5, "peer": ["10.0.0.1", 80]}),
            ),
            read_fd,
        )

        child_handle, peer, data_fd = accept_socket(client, handle=3)
        self.addCleanup(lambda: os.close(data_fd))

        self.assertEqual(
            (child_handle, peer),
            (5, ("10.0.0.1", 80)),
            msg="accept must decode the child handle and the (host, port) peer tuple in order.",
        )
        self.assertEqual(data_fd, read_fd, msg="accept must return the passed data-channel fd.")

    def test__accept__ok_without_fd_raises(self) -> None:
        """
        Ensure a RESPONSE_OK accept that carries no data-channel
        descriptor is a protocol error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = create_autospec(IpcClient, spec_set=True)
        client.request_with_fd.return_value = (
            IpcMessage(
                kind=IpcMessageKind.RESPONSE_OK,
                op=IpcOp.SOCKET_CALL,
                req_id=1,
                body=encode_socket_ok({"handle": 5, "peer": ["10.0.0.1", 80]}),
            ),
            None,
        )

        with self.assertRaises(IpcConnectionError):
            accept_socket(client, handle=3)

    def test__accept__error_response_raises_remote(self) -> None:
        """
        Ensure a RESPONSE_ERROR accept surfaces the remote error rather
        than returning.

        Reference: RFC 9293 §3.5 (accept failure).
        """

        client = create_autospec(IpcClient, spec_set=True)
        client.request_with_fd.return_value = (
            IpcMessage(
                kind=IpcMessageKind.RESPONSE_ERROR,
                op=IpcOp.SOCKET_CALL,
                req_id=1,
                body=encode_socket_error(error_type="ConnectionAbortedError", message="aborted"),
            ),
            None,
        )

        with self.assertRaises(IpcRemoteError):
            accept_socket(client, handle=3)
