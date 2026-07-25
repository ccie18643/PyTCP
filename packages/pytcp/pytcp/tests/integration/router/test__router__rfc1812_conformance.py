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
This module contains the M4 RFC 1812 conformance-sweep integration
tests for the IPv4 forwarding plane: the directed-broadcast
forward-destination filter, the deliver-before-forward ordering for a
locally-addressed low-TTL datagram, the martian-source drop that
precedes the forward branch, and byte-for-byte IP-options preservation
across a forward.

pytcp/tests/integration/router/test__router__rfc1812_conformance.py

ver 3.0.9
"""

from net_addr import Buffer, Ip4Address
from net_proto import Ip4Assembler, Ip4OptionNop, Ip4Options, UdpAssembler
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.router_testcase import HOST_D__IP4, RouterTestCase


class TestRouterRfc1812ConformanceIp4(RouterTestCase):
    """
    The M4 RFC 1812 IPv4 forwarding conformance-sweep tests.
    """

    def test__router__ip4__forward__directed_broadcast_dst_dropped(self) -> None:
        """
        Ensure a transit datagram destined to the directed broadcast of a
        directly-connected subnet is not forwarded — the smurf-amplification
        vector a router must close by default.

        Reference: RFC 1812 §5.3.5.2 (directed broadcasts not forwarded).
        Reference: RFC 2644 (default off for directed-broadcast forwarding).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=Ip4Address("10.0.2.255"),
                ttl=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_martian_dst__drop=1,
        )

    def test__router__ip4__deliver_precedes_forward__ttl1_to_local(self) -> None:
        """
        Ensure a datagram addressed to one of the router's own addresses
        is delivered locally even with TTL 1 — the deliver decision
        precedes the forward branch, so no Time Exceeded is generated for
        a locally-destined low-TTL datagram.

        Reference: RFC 1812 §5.2.1 (deliver-or-forward; local delivery first).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                ttl=1,
            ),
        )

        # The datagram was accepted as locally destined (dst_unicast),
        # so the forward-path TTL check never ran — any reply it draws
        # (e.g. a Port Unreachable) is local-delivery behaviour, never a
        # forward-path Time Exceeded.
        for frame in emitted[self.if1.ifindex]:
            self.assertNotEqual(
                frame[14 + 20],
                11,
                msg="A locally-destined low-TTL datagram must not elicit a forward-path Time Exceeded (type 11).",
            )
        self._assert_packet_stats_rx(
            exact=False,
            ip4__dst_unicast=1,
            ip4__forward_ttl_exceeded__drop=0,
            ip4__forward=0,
        )

    def test__router__ip4__martian_source_not_forwarded(self) -> None:
        """
        Ensure a transit datagram whose source address is the directed
        broadcast of a locally-connected subnet is dropped at the RX
        martian-source gate before the forward branch is reached.

        Reference: RFC 1812 §5.3.7 (source-address validation).
        Reference: RFC 1122 §3.2.1.3 (a source MUST NOT be a broadcast).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=Ip4Address("10.0.1.255"),
                dst_ip=HOST_D__IP4,
                ttl=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__src_directed_broadcast__drop=1,
        )

    def test__router__ip4__forward__preserves_ip_options(self) -> None:
        """
        Ensure a forwarded datagram carrying IPv4 header options preserves
        the option bytes and header length byte-for-byte — the router
        forwards options faithfully.

        Reference: RFC 1812 §5.2.4 (IP options on forwarded datagrams).
        """

        self._enable_forwarding()

        options = Ip4Options(Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop())
        udp = UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=b"opt-forward")
        ip4 = Ip4Assembler(
            ip4__src=HOST_A__IP4_ADDRESS,
            ip4__dst=HOST_D__IP4,
            ip4__ttl=64,
            ip4__options=options,
            ip4__payload=udp,
        )
        eth = EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=self.if1.handler._mac_unicast,
            ethernet__payload=ip4,
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        frame = b"".join(bytes(buffer) for buffer in buffers)

        emitted = self._drive_forward(ingress=self.if1, frame=frame)

        egress_frames = emitted[self.if2.ifindex]
        self.assertEqual(len(egress_frames), 1, msg="Datagram with options must be forwarded out the egress.")
        forwarded = PacketRx(egress_frames[0])
        EthernetParser(forwarded)
        Ip4Parser(forwarded)
        self.assertEqual(
            forwarded.ip4.hlen,
            ip4.hlen,
            msg="Forwarded datagram header length (with options) must be preserved.",
        )
        self.assertEqual(
            bytes(forwarded.ip4.packet_bytes)[20 : ip4.hlen],
            bytes(ip4)[20 : ip4.hlen],
            msg="Forwarded datagram IPv4 options must be preserved byte-for-byte.",
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward=1,
        )
