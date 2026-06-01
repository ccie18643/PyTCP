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
This module contains integration tests for AF_PACKET 'bind' scoping —
that binding a packet socket to an ifindex / ethertype narrows which
frames the RX tap delivers to it.

pytcp/tests/integration/packet_handler/test__packet_socket__bind.py

ver 3.0.8
"""

from typing import override
from unittest.mock import patch

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp.socket import (
    ETH_P_ALL,
    ETH_P_IP,
    SOCK_RAW,
    AddressFamily,
    socket,
)
from pytcp.socket.packet__socket import PacketSocket
from pytcp.socket.sockaddr_ll import SockAddrLl
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

_IFACE2__MAC_ADDRESS = MacAddress("02:00:00:00:00:08")
_IFACE2__IP4_HOST = Ip4IfAddr("10.0.9.7/24")


def _arp_frame() -> bytes:
    """
    Build an ARP request to the stack (ARP ethertype) for driving the
    bind-scoping tests.
    """

    return bytes(
        EthernetAssembler(
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REQUEST,
                arp__sha=HOST_A__MAC_ADDRESS,
                arp__spa=HOST_A__IP4_ADDRESS,
                arp__tpa=STACK__IP4_HOST.address,
            ),
        )
    )


class TestPacketSocketBind(NetworkTestCase):
    """
    The AF_PACKET 'bind' scoping integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the mock network and suppress packet-socket log output.
        """

        super().setUp()
        self.enterContext(patch("pytcp.socket.packet__socket.log"))

    def _packet_socket(self) -> PacketSocket:
        """
        Open a non-blocking AF_PACKET (ETH_P_ALL) socket + cleanup.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW)
        assert isinstance(sock, PacketSocket)
        sock.setblocking(False)
        self.addCleanup(sock.close)
        return sock

    def test__packet_socket__bind__matching_ifindex_receives(self) -> None:
        """
        Ensure a socket bound to an interface's own ifindex receives a
        frame arriving on that interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()
        sock.bind(SockAddrLl(ifindex=self._packet_handler._ifindex, ethertype=ETH_P_ALL))

        self._packet_handler._phrx_ethernet(PacketRx(_arp_frame()))

        _, addr = sock.recvfrom()
        self.assertEqual(
            addr.ifindex,
            self._packet_handler._ifindex,
            msg="A socket bound to an interface must receive frames arriving on it.",
        )

    def test__packet_socket__bind__other_ifindex_excluded(self) -> None:
        """
        Ensure a socket bound to one interface does not receive a frame
        arriving on a different interface — the ifindex scope excludes
        it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        added = self._add_interface(
            mac_address=_IFACE2__MAC_ADDRESS,
            ip4_host=_IFACE2__IP4_HOST,
            arp_entries={Ip4Address("10.0.9.91"): None},
        )
        sock = self._packet_socket()
        sock.bind(SockAddrLl(ifindex=added.ifindex, ethertype=ETH_P_ALL))

        # Frame arrives on the BOOT interface, not the bound one.
        self._packet_handler._phrx_ethernet(PacketRx(_arp_frame()))

        with self.assertRaises(BlockingIOError):
            sock.recv()

    def test__packet_socket__bind__ethertype_filter_excludes(self) -> None:
        """
        Ensure binding to a specific ethertype narrows the capture
        filter — an ARP frame is excluded from a socket re-bound to the
        IPv4 ethertype.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()
        sock.bind(SockAddrLl(ifindex=self._packet_handler._ifindex, ethertype=ETH_P_IP))

        self._packet_handler._phrx_ethernet(PacketRx(_arp_frame()))

        with self.assertRaises(BlockingIOError):
            sock.recv()
