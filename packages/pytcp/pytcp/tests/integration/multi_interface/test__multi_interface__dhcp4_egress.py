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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains integration tests for DHCPv4 limited-broadcast egress
on a multi-homed (multiple-interface) host.

pytcp/tests/integration/multi_interface/test__multi_interface__dhcp4_egress.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4IfAddr, Ip6IfAddr, MacAddress
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType, Dhcp4Operation
from net_proto.protocols.dhcp4.options.dhcp4__option__end import Dhcp4OptionEnd
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options
from pytcp.socket import AF_INET4, SO_BINDTODEVICE, SO_BROADCAST, SOCK_DGRAM, SOL_SOCKET, socket
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# Second interface — a distinct subnet from the harness boot interface
# (10.0.1.0/24 on interface 1), mirroring the 'make run_multi' topology
# (tap7 + tap9) that surfaced the egress ambiguity.
IFACE2__NAME = "tap-test-2"
IFACE2__MAC_ADDRESS = MacAddress("02:00:00:00:00:08")
IFACE2__IP4_HOST = Ip4IfAddr("10.0.2.7/24")
IFACE2__IP6_HOST = Ip6IfAddr("2001:db8:0:2::7/64")

# The all-ones limited broadcast a DHCPv4 client targets before it owns
# an address (RFC 2131 §4.1).
DHCP4__LIMITED_BROADCAST = "255.255.255.255"
DHCP4__CLIENT_PORT = 68
DHCP4__SERVER_PORT = 67


def _build_dhcp4_discover(*, chaddr: MacAddress) -> bytes:
    """
    Build a minimal DHCPDISCOVER datagram, mirroring the wire shape the
    real 'Dhcp4Client._send_discover' emits (broadcast flag set, message
    type DISCOVER). The egress decision under test is independent of the
    option payload, so only the mandatory message-type marker is carried.
    """

    return bytes(
        Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=0x12345678,
            dhcp4__flag_b=True,
            dhcp4__chaddr=chaddr,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
                Dhcp4OptionEnd(),
            ),
        )
    )


class TestMultiInterfaceDhcp4BroadcastEgress(IcmpTestCase, TestCase):
    """
    The multi-homed-host DHCPv4 limited-broadcast egress tests.
    """

    @override
    def setUp(self) -> None:
        """
        Add a second L2 interface so the stack is multi-homed — two
        registered interfaces on distinct subnets, the 'make run_multi'
        (tap7 + tap9) topology that exposed the DHCPv4 egress ambiguity.
        The base harness snapshots / restores 'stack.interfaces'.
        """

        super().setUp()

        # Silence the UDP socket's construct / close log lines so the
        # cleanup-time 'Closed socket' does not leak to stdout.
        self.enterContext(patch("pytcp.socket.udp__socket.log"))

        self._iface2 = self._add_interface(
            mac_address=IFACE2__MAC_ADDRESS,
            ip4_host=IFACE2__IP4_HOST,
            ip6_host=IFACE2__IP6_HOST,
        )
        # Name the second interface so SO_BINDTODEVICE can resolve it
        # (the harness '_add_interface' leaves '_interface_name' unset).
        self._iface2.handler._interface_name = IFACE2__NAME

    def test__multi_interface__dhcp4__limited_broadcast_egresses_bound_interface(self) -> None:
        """
        Ensure a DHCPv4 client on a multi-homed host that binds its
        socket to its interface (SO_BINDTODEVICE, the Linux dhclient
        model) transmits its DISCOVER to the limited broadcast
        255.255.255.255 out THAT interface — the device binding resolves
        the egress that the FIB cannot pick for the all-ones broadcast
        across multiple interfaces, so the send neither raises nor leaks
        onto another interface.

        Reference: RFC 2131 §4.1 (DHCPDISCOVER is broadcast to
        255.255.255.255 on the interface being configured).
        """

        discover = _build_dhcp4_discover(chaddr=IFACE2__MAC_ADDRESS)

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        self.addCleanup(client_socket.close)
        client_socket.bind(("0.0.0.0", DHCP4__CLIENT_PORT))
        client_socket.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, IFACE2__NAME.encode())
        # H5 SO_BROADCAST gate: limited-broadcast sends require the flag.
        client_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        client_socket.connect((DHCP4__LIMITED_BROADCAST, DHCP4__SERVER_PORT))

        boot_tx_before = len(self._frames_tx)
        iface2_tx_before = len(self._iface2.frames_tx)

        # Without SO_BINDTODEVICE the limited broadcast has no FIB-resolved
        # egress on a multi-homed host (the observed 'make run_multi'
        # RuntimeError). The device binding pins the egress to iface2.
        client_socket.send(discover)

        self.assertEqual(
            len(self._iface2.frames_tx) - iface2_tx_before,
            1,
            msg="The bound DHCPv4 DISCOVER broadcast must egress the device it is bound to (iface2).",
        )
        self.assertEqual(
            len(self._frames_tx) - boot_tx_before,
            0,
            msg="The bound DHCPv4 DISCOVER broadcast must NOT leak onto the unbound boot interface.",
        )
