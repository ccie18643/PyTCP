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
This module contains integration tests for the AF_PACKET RX tap — the
'_phrx_ethernet' fan-out that delivers a copy of each matching frame to
every bound packet socket, parallel to normal IP / ARP delivery.

pytcp/tests/integration/packet_handler/test__packet_socket__rx_tap.py

ver 3.0.8
"""

from typing import override
from unittest.mock import patch

from net_addr import MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler, EtherType
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
    MAC__BROADCAST,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

# An IPv4 multicast group MAC (224.0.0.1 -> 01:00:5e:00:00:01); its
# I/G bit is set, so 'MacAddress.is_multicast' is True.
_MULTICAST_MAC = MacAddress("01:00:5e:00:00:01")


def _arp_request_frame(*, ethernet_dst: MacAddress = STACK__MAC_ADDRESS) -> bytes:
    """
    Build an ARP request from HOST_A asking for the stack's IPv4
    address, addressed at the link layer to 'ethernet_dst' (defaults to
    the stack MAC — a frame that elicits an ARP reply so normal delivery
    is observable). Carries the ARP ethertype so packet-socket filters
    can be exercised.
    """

    return bytes(
        EthernetAssembler(
            ethernet__dst=ethernet_dst,
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REQUEST,
                arp__sha=HOST_A__MAC_ADDRESS,
                arp__spa=HOST_A__IP4_ADDRESS,
                arp__tpa=STACK__IP4_HOST.address,
            ),
        )
    )


class TestPacketSocketRxTap(NetworkTestCase):
    """
    The AF_PACKET ingress-tap integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the mock network, then suppress packet-socket log output
        so the construct / recv / close lines (the last of which fires
        from a cleanup after 'tearDown' restores 'LOG__CHANNEL') do not
        leak to stdout.
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

    def test__packet_socket__rx_tap__receives_matching_frame(self) -> None:
        """
        Ensure a frame arriving at the Ethernet RX handler is delivered
        verbatim to a bound packet socket, with a 'sockaddr_ll' carrying
        the arrival ethertype and the source MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ARP)
        frame = _arp_request_frame()

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        data, addr = sock.recvfrom()
        self.assertEqual(data, frame, msg="The packet socket must receive the complete frame verbatim.")
        self.assertEqual(addr.ethertype, EtherType.ARP, msg="sockaddr_ll.ethertype must be the frame's ethertype.")
        self.assertEqual(addr.mac, HOST_A__MAC_ADDRESS, msg="sockaddr_ll.mac must be the frame's source MAC.")
        self.assertEqual(
            addr.pkttype,
            PacketType.PACKET_HOST,
            msg="Phase 1 reports PACKET_HOST until pkttype classification lands.",
        )

    def test__packet_socket__rx_tap__is_parallel_to_ip_delivery(self) -> None:
        """
        Ensure the tap is parallel: an ARP request that a packet socket
        captures is STILL processed by the ARP handler, which emits its
        reply. The packet socket observes the frame; it does not consume
        it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ALL)
        frame = _arp_request_frame()

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            sock.recvfrom()[0],
            frame,
            msg="The ETH_P_ALL packet socket must capture the ARP request.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Normal ARP delivery must still occur — the stack emits its ARP reply.",
        )

    def test__packet_socket__rx_tap__ethertype_filter_excludes_nonmatch(self) -> None:
        """
        Ensure a packet socket bound to a different ethertype does not
        receive a frame of an unrelated ethertype — the registry's
        per-ethertype filter excludes the non-match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip_sock = self._packet_socket(protocol=ETH_P_IP)

        self._packet_handler._phrx_ethernet(PacketRx(_arp_request_frame()))

        with self.assertRaises(BlockingIOError):
            ip_sock.recv()

    def test__packet_socket__rx_tap__pkttype_classification(self) -> None:
        """
        Ensure the 'sockaddr_ll.pkttype' reflects how the frame was
        addressed at the link layer relative to this interface: the
        stack's unicast MAC is HOST, the broadcast MAC is BROADCAST, a
        multicast group MAC is MULTICAST, and any other unicast MAC is
        OTHERHOST.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ALL)

        for dst_mac, expected in (
            (STACK__MAC_ADDRESS, PacketType.PACKET_HOST),
            (MAC__BROADCAST, PacketType.PACKET_BROADCAST),
            (_MULTICAST_MAC, PacketType.PACKET_MULTICAST),
            (HOST_A__MAC_ADDRESS, PacketType.PACKET_OTHERHOST),
        ):
            with self.subTest(dst=dst_mac):
                self._packet_handler._phrx_ethernet(PacketRx(_arp_request_frame(ethernet_dst=dst_mac)))
                _, addr = sock.recvfrom()
                self.assertEqual(
                    addr.pkttype,
                    expected,
                    msg=f"A frame to {dst_mac} must classify as {expected.name}.",
                )
