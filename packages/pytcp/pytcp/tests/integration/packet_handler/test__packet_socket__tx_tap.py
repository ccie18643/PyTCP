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
This module contains integration tests for the AF_PACKET TX tap — the
'__send_out_packet' fan-out that delivers a copy of each outbound assembled
frame to every bound packet socket, tagged PACKET_OUTGOING, mirroring Linux
'dev_queue_xmit_nit'. The tap is parallel to normal transmission (a packet
socket observes egress; it does not intercept it).

pytcp/tests/integration/packet_handler/test__packet_socket__tx_tap.py

ver 3.0.8
"""

from typing import override
from unittest.mock import patch

from net_proto import (
    ArpAssembler,
    ArpOperation,
    EthernetAssembler,
    EtherType,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp.runtime.socket import (
    ETH_P_ALL,
    ETH_P_ARP,
    ETH_P_IP,
    SOCK_RAW,
    AddressFamily,
    PacketType,
    socket,
)
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)


def _arp_reply_payload() -> ArpAssembler:
    """
    Build the ARP reply the stack would send to HOST_A — the payload of an
    outbound frame that exercises the TX tap.
    """

    return ArpAssembler(
        arp__oper=ArpOperation.REPLY,
        arp__sha=STACK__MAC_ADDRESS,
        arp__spa=STACK__IP4_HOST.address,
        arp__tha=HOST_A__MAC_ADDRESS,
        arp__tpa=HOST_A__IP4_ADDRESS,
    )


def _inbound_arp_request_frame() -> bytes:
    """
    Build an inbound ARP request from HOST_A asking for the stack's IPv4
    address — a frame that elicits an ARP reply, so the stack's outbound
    reply is observable on the TX tap.
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


class TestPacketSocketTxTap(NetworkTestCase):
    """
    The AF_PACKET egress-tap integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the mock network, then suppress packet-socket log output so
        the construct / recv / close lines do not leak to stdout.
        """

        super().setUp()
        self.enterContext(patch("pytcp.runtime.socket.packet__socket.log"))

    def _packet_socket(self, *, protocol: EtherType | int) -> PacketSocket:
        """
        Open a non-blocking AF_PACKET socket and register cleanup.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW, protocol=protocol)
        assert isinstance(sock, PacketSocket)
        sock.setblocking(False)
        self.addCleanup(sock.close)
        return sock

    def test__packet_socket__tx_tap__captures_outbound_frame(self) -> None:
        """
        Ensure an assembled frame the stack transmits is delivered verbatim
        to a bound packet socket, with a 'sockaddr_ll' carrying the frame's
        ethertype, the source MAC, and 'pkttype' PACKET_OUTGOING.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ARP)
        expected = bytes(
            EthernetAssembler(
                ethernet__src=STACK__MAC_ADDRESS,
                ethernet__dst=HOST_A__MAC_ADDRESS,
                ethernet__payload=_arp_reply_payload(),
            )
        )

        self._packet_handler._phtx_ethernet(
            ethernet__src=STACK__MAC_ADDRESS,
            ethernet__dst=HOST_A__MAC_ADDRESS,
            ethernet__payload=_arp_reply_payload(),
        )

        data, addr = sock.recvfrom()
        self.assertEqual(data, expected, msg="The packet socket must receive the outbound frame verbatim.")
        self.assertEqual(addr.ethertype, EtherType.ARP, msg="sockaddr_ll.ethertype must be the frame's ethertype.")
        self.assertEqual(addr.mac, STACK__MAC_ADDRESS, msg="sockaddr_ll.mac must be the outbound frame's source MAC.")
        self.assertEqual(
            addr.pkttype,
            PacketType.PACKET_OUTGOING,
            msg="An outbound frame must be tagged PACKET_OUTGOING.",
        )

    def test__packet_socket__tx_tap__captures_stack_reply_to_inbound_request(self) -> None:
        """
        Ensure the tap fires on the natural reply path: an inbound ARP
        request the stack answers is captured twice by an ETH_P_ALL socket —
        the inbound request (PACKET_HOST) and the stack's outbound reply
        (PACKET_OUTGOING).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ALL)

        self._packet_handler._phrx_ethernet(PacketRx(_inbound_arp_request_frame()))

        _, inbound_addr = sock.recvfrom()
        self.assertEqual(
            inbound_addr.pkttype,
            PacketType.PACKET_HOST,
            msg="The inbound ARP request must be captured as PACKET_HOST.",
        )

        _, outbound_addr = sock.recvfrom()
        self.assertEqual(
            outbound_addr.pkttype,
            PacketType.PACKET_OUTGOING,
            msg="The stack's outbound ARP reply must be captured as PACKET_OUTGOING.",
        )
        self.assertEqual(
            outbound_addr.mac,
            STACK__MAC_ADDRESS,
            msg="The outbound reply's source MAC must be the stack MAC.",
        )

    def test__packet_socket__tx_tap__ethertype_filter_excludes_nonmatch(self) -> None:
        """
        Ensure a packet socket bound to a different ethertype does not
        capture an outbound frame of an unrelated ethertype — the registry's
        per-ethertype filter excludes the non-match on egress too.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip_sock = self._packet_socket(protocol=ETH_P_IP)

        self._packet_handler._phtx_ethernet(
            ethernet__src=STACK__MAC_ADDRESS,
            ethernet__dst=HOST_A__MAC_ADDRESS,
            ethernet__payload=_arp_reply_payload(),
        )

        with self.assertRaises(BlockingIOError):
            ip_sock.recv()
