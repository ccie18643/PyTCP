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
This module contains integration tests for the loopback AF_PACKET tap —
the fan-out that delivers a synthetic-framed copy of each internally
looped ('lo') IP packet to every bound packet socket. It is what lets the
in-stack 'pytcp tcpdump' observe stack-internal loopback traffic that an
external capture tool (watching the TAP device) is structurally blind to.

pytcp/tests/integration/loopback/test__loopback__packet_tap.py

ver 3.0.8
"""

from typing import override
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address
from net_proto import EtherType, Ip4Assembler, Ip6Assembler
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp.cli.cli__tcpdump import describe_frame
from pytcp.runtime.socket import (
    ETH_P_ALL,
    SOCK_RAW,
    AddressFamily,
    PacketType,
    socket,
)
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.tests.lib.network_testcase import NetworkTestCase


def _loopback_ip4_udp() -> bytes:
    """
    Build a bare IPv4/UDP packet from 127.0.0.1:12345 to 127.0.0.1:7 —
    the form an internally looped datagram takes on the loopback ring.
    """

    return bytes(
        Ip4Assembler(
            ip4__src=Ip4Address("127.0.0.1"),
            ip4__dst=Ip4Address("127.0.0.1"),
            ip4__payload=UdpAssembler(udp__sport=12345, udp__dport=7, udp__payload=b"lo"),
        )
    )


def _loopback_ip6_udp() -> bytes:
    """
    Build a bare IPv6/UDP packet from ::1:12345 to ::1:7.
    """

    return bytes(
        Ip6Assembler(
            ip6__src=Ip6Address("::1"),
            ip6__dst=Ip6Address("::1"),
            ip6__payload=UdpAssembler(udp__sport=12345, udp__dport=7, udp__payload=b"lo"),
        )
    )


class TestLoopbackPacketTap(NetworkTestCase):
    """
    The loopback AF_PACKET egress-tap integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Bring up the boot + loopback interfaces and silence packet-socket
        log output.
        """

        super().setUp()
        self.enterContext(patch("pytcp.runtime.socket.packet__socket.log"))
        self._lo = self._register_loopback()

    def _packet_socket(self, *, protocol: EtherType | int) -> PacketSocket:
        """
        Open a non-blocking AF_PACKET socket and register cleanup.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW, protocol=protocol)
        assert isinstance(sock, PacketSocket)
        sock.setblocking(False)
        self.addCleanup(sock.close)
        return sock

    def test__loopback__tap_delivers_raw_ipv4(self) -> None:
        """
        Ensure a looped IPv4 packet is delivered to a bound packet socket
        as the bare IP packet (the loopback interface has no link layer),
        with 'sockaddr_ll' carrying the IPv4 ethertype and PACKET_HOST.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ALL)
        ip4 = _loopback_ip4_udp()

        with patch.object(self._lo, "_phrx_ip4"):
            self._lo._deliver_loopback(PacketRx(ip4))

        data, addr = sock.recvfrom()
        self.assertEqual(data, ip4, msg="The looped IPv4 packet must be delivered as the bare IP packet.")
        self.assertEqual(
            addr.ethertype, EtherType.IP4, msg="sockaddr_ll.ethertype must be IPv4 for a looped IPv4 packet."
        )
        self.assertEqual(addr.pkttype, PacketType.PACKET_HOST, msg="A looped packet is locally destined — PACKET_HOST.")

    def test__loopback__tap_frame_decodes_in_stack(self) -> None:
        """
        Ensure the synthetic-framed loopback copy decodes through the
        'pytcp tcpdump' engine to a readable line — the capability an
        external tool watching the TAP device cannot provide.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ALL)

        with patch.object(self._lo, "_phrx_ip4"):
            self._lo._deliver_loopback(PacketRx(_loopback_ip4_udp()))

        data, _ = sock.recvfrom()
        self.assertEqual(
            describe_frame(data),
            "IP 127.0.0.1.12345 > 127.0.0.1.7: UDP, length 2",
            msg="The looped frame must decode to a readable tcpdump-style line.",
        )

    def test__loopback__tap_delivers_raw_ipv6(self) -> None:
        """
        Ensure a looped IPv6 packet is delivered as the bare IP packet with
        the IPv6 ethertype in 'sockaddr_ll'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket(protocol=ETH_P_ALL)
        ip6 = _loopback_ip6_udp()

        with patch.object(self._lo, "_phrx_ip6"):
            self._lo._deliver_loopback(PacketRx(ip6))

        data, addr = sock.recvfrom()
        self.assertEqual(data, ip6, msg="The looped IPv6 packet must be delivered as the bare IP packet.")
        self.assertEqual(
            addr.ethertype, EtherType.IP6, msg="sockaddr_ll.ethertype must be IPv6 for a looped IPv6 packet."
        )

    def test__loopback__no_packet_socket_bound_is_a_noop(self) -> None:
        """
        Ensure the tap short-circuits when no packet socket is bound, so
        the normal loopback delivery path is untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(self._lo, "_phrx_ip4") as phrx:
            self._lo._deliver_loopback(PacketRx(_loopback_ip4_udp()))

        phrx.assert_called_once()

    def test__loopback__parser_still_consumes_the_looped_packet(self) -> None:
        """
        Ensure the tap does not disturb the real RX path: after the tap
        copy, the packet is still dispatched into the IPv4 RX handler.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_socket(protocol=ETH_P_ALL)

        with patch.object(self._lo, "_phrx_ip4") as phrx:
            self._lo._deliver_loopback(PacketRx(_loopback_ip4_udp()))

        phrx.assert_called_once()

    def test__loopback__ethertype_filtered_socket_excludes_other_family(self) -> None:
        """
        Ensure a packet socket bound to the IPv4 ethertype does not capture
        a looped IPv6 packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip4_sock = self._packet_socket(protocol=EtherType.IP4)

        with patch.object(self._lo, "_phrx_ip6"):
            self._lo._deliver_loopback(PacketRx(_loopback_ip6_udp()))

        with self.assertRaises(BlockingIOError):
            ip4_sock.recv()
