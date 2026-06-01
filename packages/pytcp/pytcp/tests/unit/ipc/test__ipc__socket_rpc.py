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

ver 3.0.8
"""

from unittest import TestCase

from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.ipc.ipc__socket_rpc import (
    SocketRequest,
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
