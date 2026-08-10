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
This module contains the real-TAP end-to-end smoke tests — the root-gated
suite that boots the real daemon on an actual TAP and exercises the OS
edges (/dev/net/tun I/O, the real Tx/Rx rings, real threads + timers) the
wire-level integration tests mock. Skipped unless run as root with
PYTCP_REAL_TAP=1.

pytcp/tests/integration/real_tap/test__real_tap__smoke.py

ver 3.0.10
"""

from typing import cast

from net_proto import (
    Icmp4Assembler,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp6Assembler,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6NdMessageNeighborAdvertisement,
    UdpAssembler,
)
from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.arp.arp__assembler import ArpAssembler
from net_proto.protocols.arp.arp__enums import ArpOperation
from net_proto.protocols.arp.arp__parser import ArpParser
from net_proto.protocols.icmp4.icmp4__parser import Icmp4Parser
from net_proto.protocols.icmp6.icmp6__parser import Icmp6Parser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.udp.udp__parser import UdpParser
from pytcp.client.client__datagram_socket import ClientUdpSocket
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.tests.lib.real_tap_testcase import RealTapTestCase

_STACK_PORT = 40100
_PEER_PORT = 40200


class TestRealTapSmoke(RealTapTestCase):
    """
    The real-TAP end-to-end smoke tests.
    """

    def test__real_tap__daemon_boots_and_serves_ipc(self) -> None:
        """
        Ensure the real daemon booted on the tap serves the control
        socket — a drop-in client connects and opens a socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._client()
        sock = client.socket(AddressFamily.INET4, SocketType.DGRAM)
        self.assertIsNotNone(sock, msg="The booted daemon must serve a drop-in socket over its control boundary.")
        sock.close()

    def test__real_tap__arp_request_elicits_reply(self) -> None:
        """
        Ensure an ARP Request for the stack's IPv4 address elicits a real
        ARP Reply on the wire (real RxRing -> ArpCache -> real TxRing ->
        /dev/net/tun).

        Reference: RFC 826 (ARP request / reply).
        """

        request = ArpAssembler(
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.PEER_MAC,
            arp__spa=self.PEER_IP4,
            arp__tha=self.PEER_MAC,
            arp__tpa=self.STACK_IP4.address,
        )
        self._peer_send(self._build_eth(dst=self.STACK_MAC, payload=request))

        def _is_arp_reply(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.ARP:
                return False
            ArpParser(packet_rx)
            return packet_rx.arp.oper is ArpOperation.REPLY and packet_rx.arp.spa == self.STACK_IP4.address

        reply = self._peer_expect(_is_arp_reply)
        self.assertEqual(
            reply.arp.sha,
            self.STACK_MAC,
            msg="The ARP Reply must carry the stack's MAC as the sender hardware address.",
        )

    def test__real_tap__icmp4_echo_request_elicits_reply(self) -> None:
        """
        Ensure an ICMPv4 Echo Request to the stack elicits a real Echo
        Reply on the wire, resolving the peer's neighbor entry first.

        Reference: RFC 792 (ICMP Echo / Echo Reply).
        """

        self._prime_peer_neighbor()

        echo = Icmp4Assembler(icmp4__message=Icmp4MessageEchoRequest(id=0x1234, seq=1, data=b"real-tap-ping"))
        ip4 = Ip4Assembler(ip4__src=self.PEER_IP4, ip4__dst=self.STACK_IP4.address, ip4__payload=echo)
        self._peer_send(self._build_eth(dst=self.STACK_MAC, payload=ip4))

        def _is_echo_reply(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP4:
                return False
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is not IpProto.ICMP4:
                return False
            Icmp4Parser(packet_rx)
            return isinstance(packet_rx.icmp4.message, Icmp4MessageEchoReply)

        reply = self._peer_expect(_is_echo_reply)
        self.assertEqual(
            bytes(cast(Icmp4MessageEchoReply, reply.icmp4.message).data),
            b"real-tap-ping",
            msg="The Echo Reply must echo the request payload.",
        )

    def test__real_tap__icmp6_nd_solicitation_elicits_advertisement(self) -> None:
        """
        Ensure a Neighbor Solicitation for the stack's IPv6 address
        elicits a real Neighbor Advertisement on the wire (real RxRing ->
        NdCache -> real TxRing -> /dev/net/tun).

        Reference: RFC 4861 §7.2.4 (Neighbor Advertisement sent in response to a solicitation).
        """

        self._peer_send(self._ns_to_stack_frame())

        def _is_na(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP6:
                return False
            Ip6Parser(packet_rx)
            if packet_rx.ip6.next is not IpProto.ICMP6:
                return False
            Icmp6Parser(packet_rx)
            message = packet_rx.icmp6.message
            return (
                isinstance(message, Icmp6NdMessageNeighborAdvertisement)
                and message.target_address == self.STACK_IP6.address
            )

        reply = self._peer_expect(_is_na, timeout=5.0)
        self.assertEqual(
            cast(Icmp6NdMessageNeighborAdvertisement, reply.icmp6.message).target_address,
            self.STACK_IP6.address,
            msg="The Neighbor Advertisement must advertise the stack's solicited IPv6 address.",
        )

    def test__real_tap__icmp6_echo_request_elicits_reply(self) -> None:
        """
        Ensure an ICMPv6 Echo Request to the stack elicits a real Echo
        Reply on the wire, resolving the peer's neighbor entry first.

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        self._prime_peer_neighbor6()

        echo = Icmp6Assembler(icmp6__message=Icmp6MessageEchoRequest(id=0x4321, seq=1, data=b"real-tap-ping6"))
        ip6 = Ip6Assembler(ip6__src=self.PEER_IP6, ip6__dst=self.STACK_IP6.address, ip6__payload=echo)
        self._peer_send(self._build_eth(dst=self.STACK_MAC, payload=ip6))

        def _is_echo6_reply(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP6:
                return False
            Ip6Parser(packet_rx)
            if packet_rx.ip6.next is not IpProto.ICMP6:
                return False
            Icmp6Parser(packet_rx)
            return isinstance(packet_rx.icmp6.message, Icmp6MessageEchoReply)

        reply = self._peer_expect(_is_echo6_reply, timeout=5.0)
        self.assertEqual(
            bytes(cast(Icmp6MessageEchoReply, reply.icmp6.message).data),
            b"real-tap-ping6",
            msg="The ICMPv6 Echo Reply must echo the request payload.",
        )

    def test__real_tap__udp_send_resolves_neighbor_via_real_arp(self) -> None:
        """
        Ensure a UDP datagram sent through the drop-in socket to an
        unresolved peer drives a real ARP resolution and is then delivered
        on the wire — exercising the real neighbor cache + pending-queue
        flush + Tx ring.

        Reference: RFC 826 (ARP resolution on transmit).
        """

        sock = cast(ClientUdpSocket, self._client().socket(AddressFamily.INET4, SocketType.DGRAM))
        sock.settimeout(5.0)
        sock.bind((str(self.STACK_IP4.address), _STACK_PORT))
        sock.sendto(b"resolve-me", (str(self.PEER_IP4), _PEER_PORT))

        # The stack has no neighbor entry -> it ARP-requests the peer;
        # answer it so the queued datagram flushes to the wire.
        self._answer_arp_for_peer(timeout=5.0)

        def _is_udp_to_peer(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP4:
                return False
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is not IpProto.UDP or packet_rx.ip4.dst != self.PEER_IP4:
                return False
            UdpParser(packet_rx)
            return packet_rx.udp.dport == _PEER_PORT

        datagram = self._peer_expect(_is_udp_to_peer, timeout=5.0)
        self.assertEqual(
            bytes(datagram.udp.payload),
            b"resolve-me",
            msg="The delivered UDP datagram must carry the sent payload.",
        )
        sock.close()

    def test__real_tap__udp_echo_round_trip(self) -> None:
        """
        Ensure a full UDP round trip works through the real stack: the
        drop-in client sends to the peer, the peer echoes off the wire,
        and the client receives the reply.

        Reference: RFC 768 (UDP datagram delivery).
        """

        self._prime_peer_neighbor()

        sock = cast(ClientUdpSocket, self._client().socket(AddressFamily.INET4, SocketType.DGRAM))
        sock.settimeout(5.0)
        sock.bind((str(self.STACK_IP4.address), _STACK_PORT))
        sock.sendto(b"ping", (str(self.PEER_IP4), _PEER_PORT))

        def _is_udp_to_peer(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP4:
                return False
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is not IpProto.UDP or packet_rx.ip4.dst != self.PEER_IP4:
                return False
            UdpParser(packet_rx)
            return packet_rx.udp.dport == _PEER_PORT

        request = self._peer_expect(_is_udp_to_peer, timeout=5.0)
        self.assertEqual(bytes(request.udp.payload), b"ping", msg="The stack must send the UDP request on the wire.")

        # Echo it back: peer -> stack, swapping the ports.
        reply_udp = UdpAssembler(udp__sport=_PEER_PORT, udp__dport=_STACK_PORT, udp__payload=b"pong")
        reply_ip4 = Ip4Assembler(ip4__src=self.PEER_IP4, ip4__dst=self.STACK_IP4.address, ip4__payload=reply_udp)
        self._peer_send(self._build_eth(dst=self.STACK_MAC, payload=reply_ip4))

        data, address = sock.recvfrom()
        self.assertEqual(data, b"pong", msg="The client must receive the peer's UDP echo through the real stack.")
        self.assertEqual(
            address,
            (str(self.PEER_IP4), _PEER_PORT),
            msg="The received datagram's source must be the peer address/port.",
        )
        sock.close()
