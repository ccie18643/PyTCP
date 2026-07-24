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
This module contains integration tests for the IP_ADD_MEMBERSHIP /
IP_DROP_MEMBERSHIP socket options.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__socket_membership_opts.py

ver 3.0.8
"""

import sys
from typing import override

from net_addr import Ip4Address, MacAddress
from pytcp import stack
from pytcp.runtime.socket import (
    AF_INET,
    IP_ADD_MEMBERSHIP,
    IP_DROP_MEMBERSHIP,
    IPPROTO_IP,
    SOCK_DGRAM,
    socket,
)
from pytcp.tests.lib.network_testcase import NetworkTestCase

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / socket log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _ip_mreq(group: str, interface: str) -> bytes:
    """Pack an 8-byte ip_mreq (imr_multiaddr + imr_interface)."""

    return bytes(Ip4Address(group)) + bytes(Ip4Address(interface))


class TestIgmpSocketMembershipOptions(NetworkTestCase):
    """
    The IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP socket-option tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and open a datagram socket for the options.
        """

        super().setUp()
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(self._socket.close)

    def test__socket__add_membership_inaddr_any_joins_group(self) -> None:
        """
        Ensure setsockopt(IP_ADD_MEMBERSHIP) with an INADDR_ANY
        interface joins the group on the IPv4-capable interface and
        programs its multicast MAC.

        Reference: RFC 1112 §4 (host joins multicast groups).
        Reference: RFC 1112 §6.4 (IPv4-to-Ethernet multicast MAC mapping).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq("239.1.1.1", "0.0.0.0"))

        self.assertIn(Ip4Address("239.1.1.1"), self._packet_handler._ip4_multicast)
        self.assertIn(MacAddress("01:00:5e:01:01:01"), self._packet_handler._mac_multicast)

    def test__socket__drop_membership_leaves_group(self) -> None:
        """
        Ensure setsockopt(IP_DROP_MEMBERSHIP) leaves a previously joined
        group.

        Reference: RFC 1112 §4 (host leaves multicast groups).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq("239.1.1.1", "0.0.0.0"))
        self._socket.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, _ip_mreq("239.1.1.1", "0.0.0.0"))

        self.assertNotIn(Ip4Address("239.1.1.1"), self._packet_handler._ip4_multicast)

    def test__socket__add_membership_specific_interface(self) -> None:
        """
        Ensure setsockopt(IP_ADD_MEMBERSHIP) with a specific
        imr_interface address joins on the interface that owns it.

        Reference: RFC 1112 §4 (membership is per interface).
        """

        interface_address = self._packet_handler._ip4_unicast[0]

        self._socket.setsockopt(
            IPPROTO_IP,
            IP_ADD_MEMBERSHIP,
            _ip_mreq("239.2.2.2", str(interface_address)),
        )

        self.assertIn(Ip4Address("239.2.2.2"), self._packet_handler._ip4_multicast)

    def test__socket__add_membership_rejects_non_multicast_group(self) -> None:
        """
        Ensure setsockopt(IP_ADD_MEMBERSHIP) with a non-multicast group
        address raises OSError(EINVAL).

        Reference: RFC 1112 §4 (membership is for multicast groups).
        """

        with self.assertRaises(OSError):
            self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq("192.0.2.1", "0.0.0.0"))

    def test__socket__add_membership_ip_mreqn_explicit_ifindex_takes_precedence(self) -> None:
        """
        Ensure setsockopt(IP_ADD_MEMBERSHIP) with a 12-byte ip_mreqn
        joins on the interface named by imr_ifindex, even when
        imr_address matches no interface (the explicit ifindex wins).

        Reference: PyTCP test infrastructure (ip_mreqn parity, no RFC clause).
        """

        ifindex = self._packet_handler._ifindex
        mreqn = (
            bytes(Ip4Address("239.3.3.3"))  # imr_multiaddr
            + bytes(Ip4Address("192.0.2.123"))  # imr_address (not owned by any interface)
            + ifindex.to_bytes(4, sys.byteorder)  # imr_ifindex (host order, C int)
        )

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mreqn)

        self.assertIn(Ip4Address("239.3.3.3"), self._packet_handler._ip4_multicast)

    def test__socket__add_membership_ip_mreqn_zero_ifindex_falls_back_to_address(self) -> None:
        """
        Ensure a 12-byte ip_mreqn with imr_ifindex 0 falls back to
        selecting the interface by imr_address.

        Reference: PyTCP test infrastructure (ip_mreqn parity, no RFC clause).
        """

        interface_address = self._packet_handler._ip4_unicast[0]
        mreqn = bytes(Ip4Address("239.4.4.4")) + bytes(interface_address) + (0).to_bytes(4, sys.byteorder)

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mreqn)

        self.assertIn(Ip4Address("239.4.4.4"), self._packet_handler._ip4_multicast)

    def test__socket__add_membership_rejects_short_mreq(self) -> None:
        """
        Ensure setsockopt(IP_ADD_MEMBERSHIP) with a truncated ip_mreq
        (fewer than 8 octets) raises OSError(EINVAL).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(OSError):
            self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, b"\xef\x01\x01")
