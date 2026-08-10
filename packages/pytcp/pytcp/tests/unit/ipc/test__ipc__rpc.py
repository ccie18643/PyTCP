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
Tests for the IPC control-plane RPC body codec.

pytcp/tests/unit/ipc/test__ipc__rpc.py

ver 3.0.9
"""

from unittest import TestCase

from net_addr import Ip4Address
from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.ipc.ipc__rpc import (
    ControlRequest,
    decode_control_request,
    decode_control_value,
    encode_control_error,
    encode_control_ok,
    encode_control_request,
    raise_control_error,
)


class TestIpcRpcRequest(TestCase):
    """
    The IPC control-request body codec tests.
    """

    def test__ipc__rpc__request_round_trip_with_typed_args(self) -> None:
        """
        Ensure a control request round-trips through encode/decode with
        its api, method, interface scope, and typed keyword arguments
        all preserved (a net_addr argument survives as the same value).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        decoded = decode_control_request(
            encode_control_request(
                api="neighbor",
                method="add",
                ifindex=2,
                args={"ip": Ip4Address("10.0.1.91")},
            )
        )

        self.assertEqual(
            decoded,
            ControlRequest(
                api="neighbor",
                method="add",
                ifindex=2,
                args={"ip": Ip4Address("10.0.1.91")},
            ),
            msg="A control request must round-trip with its typed args preserved.",
        )

    def test__ipc__rpc__request_round_trip_no_scope(self) -> None:
        """
        Ensure a control request with no interface scope round-trips
        with 'ifindex' decoded as None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        decoded = decode_control_request(
            encode_control_request(api="sysctl", method="list_keys", ifindex=None, args={})
        )

        self.assertIsNone(
            decoded.ifindex,
            msg="An unscoped control request must decode 'ifindex' as None.",
        )


class TestIpcRpcResponse(TestCase):
    """
    The IPC control-response body codec tests.
    """

    def test__ipc__rpc__ok_round_trip(self) -> None:
        """
        Ensure a successful result round-trips through encode/decode,
        preserving its value and type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            decode_control_value(encode_control_ok([Ip4Address("10.0.1.1"), 42])),
            [Ip4Address("10.0.1.1"), 42],
            msg="A successful result must round-trip with value and type preserved.",
        )

    def test__ipc__rpc__error_raises_remote_error(self) -> None:
        """
        Ensure an encoded error body re-raises as an 'IpcRemoteError'
        carrying the remote exception's type name and message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcRemoteError) as error:
            raise_control_error(
                encode_control_error(error_type="KeyError", message="'no.such.key'"),
            )

        self.assertEqual(
            (error.exception.error_type, error.exception.remote_message, str(error.exception)),
            ("KeyError", "'no.such.key'", "[IPC] KeyError: 'no.such.key'"),
            msg="A control error must re-raise as IpcRemoteError with the remote type and message.",
        )
