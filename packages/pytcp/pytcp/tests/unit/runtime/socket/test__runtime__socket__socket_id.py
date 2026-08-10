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
This module contains tests for the 'SocketId' identifier dataclass.

pytcp/tests/unit/runtime/socket/test__runtime__socket__socket_id.py

ver 3.0.10
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.socket_id import SocketId


class TestSocketId(TestCase):
    """
    The 'SocketId' dataclass behavior tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a canonical IPv4 TCP socket identifier used by the tests.
        """

        self._socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_address=Ip4Address("10.0.0.2"),
            remote_port=9090,
        )

    def test__socket_id__stores_every_field(self) -> None:
        """
        Ensure 'SocketId' stores every keyword-only field verbatim so
        consumers can reconstruct the socket tuple without conversion.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._socket_id.address_family,
            AddressFamily.INET4,
            msg="SocketId must store the 'address_family' field verbatim.",
        )
        self.assertEqual(
            self._socket_id.socket_type,
            SocketType.STREAM,
            msg="SocketId must store the 'socket_type' field verbatim.",
        )
        self.assertEqual(
            self._socket_id.local_address,
            Ip4Address("10.0.0.1"),
            msg="SocketId must store the 'local_address' field verbatim.",
        )
        self.assertEqual(
            self._socket_id.local_port,
            8080,
            msg="SocketId must store the 'local_port' field verbatim.",
        )
        self.assertEqual(
            self._socket_id.remote_address,
            Ip4Address("10.0.0.2"),
            msg="SocketId must store the 'remote_address' field verbatim.",
        )
        self.assertEqual(
            self._socket_id.remote_port,
            9090,
            msg="SocketId must store the 'remote_port' field verbatim.",
        )

    def test__socket_id__is_frozen(self) -> None:
        """
        Ensure 'SocketId' is immutable — the 'frozen=True' dataclass
        flag must prevent attribute assignment. Stack code uses
        'SocketId' as a dict key, so hashability must not be broken
        by mutation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(FrozenInstanceError):
            self._socket_id.local_port = 4444  # type: ignore[misc]

    def test__socket_id__is_hashable(self) -> None:
        """
        Ensure 'SocketId' is hashable so it can be used as a dictionary
        key in 'stack.sockets'. Frozen dataclasses with 'slots=True' are
        hashable by default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        try:
            hash(self._socket_id)
        except TypeError as exc:  # pragma: no cover - fail path
            self.fail(f"SocketId must be hashable; got {exc!r}.")

    def test__socket_id__equal_tuples_compare_equal(self) -> None:
        """
        Ensure two 'SocketId' objects built from the same field values
        compare equal. This is the contract 'stack.sockets[id]' lookups
        rely on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        other = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_address=Ip4Address("10.0.0.2"),
            remote_port=9090,
        )

        self.assertEqual(
            self._socket_id,
            other,
            msg="SocketId objects with identical fields must compare equal.",
        )
        self.assertEqual(
            hash(self._socket_id),
            hash(other),
            msg="Equal SocketId objects must hash to the same value.",
        )

    def test__socket_id__different_field_compares_unequal(self) -> None:
        """
        Ensure any differing field produces a non-equal 'SocketId'. The
        local-port field is used here as a representative perturbation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        other = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=Ip4Address("10.0.0.1"),
            local_port=8081,
            remote_address=Ip4Address("10.0.0.2"),
            remote_port=9090,
        )

        self.assertNotEqual(
            self._socket_id,
            other,
            msg="SocketId objects with a different 'local_port' must not compare equal.",
        )

    def test__socket_id__accepts_ipv6_addresses(self) -> None:
        """
        Ensure 'SocketId' accepts 'Ip6Address' values for IPv6 sockets —
        the 'Address' annotation on local/remote fields is the base
        class for both 'Ip4Address' and 'Ip6Address'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.DGRAM,
            local_address=Ip6Address("2001:db8::1"),
            local_port=53,
            remote_address=Ip6Address("2001:db8::2"),
            remote_port=53,
        )

        self.assertEqual(
            socket_id.local_address,
            Ip6Address("2001:db8::1"),
            msg="SocketId must accept 'Ip6Address' for the local address field.",
        )
        self.assertEqual(
            socket_id.remote_address,
            Ip6Address("2001:db8::2"),
            msg="SocketId must accept 'Ip6Address' for the remote address field.",
        )
