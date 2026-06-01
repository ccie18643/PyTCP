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
This module contains the first multi-interface (N>1) integration
tests. They register a second L2 interface on a distinct IPv4 / IPv6
subnet alongside the harness's boot interface and verify that an
inbound Echo Request delivered to one interface is answered ONLY on
that interface — using that interface's own addresses and its own
neighbor cache — proving the multi-homed-host RX→reply path is
partitioned per interface (the handler instance IS the interface).

pytcp/tests/integration/multi_interface/test__multi_interface__rx_reply_isolation.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip4IfAddr, Ip6IfAddr, MacAddress
from net_proto import Icmp4MessageEchoRequest
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from pytcp import stack
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)

# Second interface — a distinct subnet from the harness boot interface
# (10.0.1.0/24 on interface 1). The on-link host that probes it lives
# on interface 2's IPv4 subnet so its MAC resolves through interface
# 2's own ARP cache, never interface 1's.
IFACE2__IFINDEX = 2
IFACE2__MAC_ADDRESS = MacAddress("02:00:00:00:00:08")
IFACE2__IP4_HOST = Ip4IfAddr("10.0.2.7/24")
IFACE2__IP6_HOST = Ip6IfAddr("2001:db8:0:2::7/64")
IFACE2__PEER__IP4_ADDRESS = Ip4Address("10.0.2.91")
IFACE2__PEER__MAC_ADDRESS = MacAddress("02:00:00:00:00:98")


def _build_icmp4_echo_frame(
    *,
    eth_src: MacAddress,
    eth_dst: MacAddress,
    ip_src: Ip4Address,
    ip_dst: Ip4Address,
    icmp_id: int = 0xCAFE,
    icmp_seq: int = 1,
    icmp_data: bytes = b"ping",
) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Echo Request frame aimed at one of
    the stack's interface addresses from an on-link peer.
    """

    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageEchoRequest(id=icmp_id, seq=icmp_seq, data=icmp_data),
    )
    ip4 = Ip4Assembler(ip4__src=ip_src, ip4__dst=ip_dst, ip4__payload=icmp)
    eth = EthernetAssembler(ethernet__src=eth_src, ethernet__dst=eth_dst, ethernet__payload=ip4)
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


class TestMultiInterfaceRxReplyIsolation(IcmpTestCase, TestCase):
    """
    The multi-homed-host per-interface RX→reply isolation tests.
    """

    def setUp(self) -> None:
        """
        Add a second L2 interface on a distinct subnet on top of the ICMP
        harness boot interface via the reusable '_add_interface' helper —
        it gets its own TX ring, its own ARP / ND caches (driven by the
        iface-2 peer entry), and ifindex 2. The base harness snapshots /
        restores 'stack.interfaces'.
        """

        super().setUp()

        self._iface2 = self._add_interface(
            mac_address=IFACE2__MAC_ADDRESS,
            ip4_host=IFACE2__IP4_HOST,
            ip6_host=IFACE2__IP6_HOST,
            arp_entries={IFACE2__PEER__IP4_ADDRESS: IFACE2__PEER__MAC_ADDRESS},
        )

    def test__multi_interface__second_interface_gets_next_ifindex(self) -> None:
        """
        Ensure '_add_interface' allocates the next free ifindex after the
        boot interface (ifindex 1), so the second interface is ifindex 2.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._iface2.ifindex,
            IFACE2__IFINDEX,
            msg="The second interface must be allocated ifindex 2 (after the boot interface's 1).",
        )

    def test__multi_interface__echo_to_iface1__reply_only_on_iface1(self) -> None:
        """
        Ensure an Echo Request delivered to the boot interface is
        answered only on the boot interface — the second interface
        emits nothing — confirming a frame's reply egresses the
        interface it ingressed on.

        Reference: RFC 1122 §3.2.2.6 (host SHOULD reply to unicast Echo).
        """

        frames_tx_1 = self._drive_rx(
            frame=_build_icmp4_echo_frame(
                eth_src=HOST_A__MAC_ADDRESS,
                eth_dst=STACK__MAC_ADDRESS,
                ip_src=HOST_A__IP4_ADDRESS,
                ip_dst=STACK__IP4_HOST.address,
            ),
        )

        self.assertEqual(
            len(frames_tx_1),
            1,
            msg="Echo Request to interface 1 must produce exactly one reply on interface 1.",
        )
        self.assertEqual(
            self._iface2.frames_tx,
            [],
            msg="Interface 2 must emit nothing for a frame that ingressed on interface 1.",
        )
        probe = self._parse_tx_icmp4(frames_tx_1[0])
        self.assertEqual(
            probe.ip_src,
            STACK__IP4_HOST.address,
            msg=f"Reply must source from interface 1's address. Got: {probe!r}",
        )

    def test__multi_interface__echo_to_iface2__reply_only_on_iface2(self) -> None:
        """
        Ensure an Echo Request delivered to the second interface is
        answered only on the second interface, sourced from that
        interface's own address and addressed to the peer's MAC
        resolved through that interface's own ARP cache.

        Reference: RFC 1122 §3.2.2.6 (host SHOULD reply to unicast Echo).
        """

        frames_tx_2 = self._iface2.drive_rx(
            frame=_build_icmp4_echo_frame(
                eth_src=IFACE2__PEER__MAC_ADDRESS,
                eth_dst=IFACE2__MAC_ADDRESS,
                ip_src=IFACE2__PEER__IP4_ADDRESS,
                ip_dst=IFACE2__IP4_HOST.address,
            ),
        )

        self.assertEqual(
            len(frames_tx_2),
            1,
            msg="Echo Request to interface 2 must produce exactly one reply on interface 2.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="Interface 1 must emit nothing for a frame that ingressed on interface 2.",
        )
        probe = self._parse_tx_icmp4(frames_tx_2[0])
        self.assertEqual(
            probe.ip_src,
            IFACE2__IP4_HOST.address,
            msg=f"Reply must source from interface 2's address. Got: {probe!r}",
        )
        self.assertEqual(
            probe.eth_src,
            IFACE2__MAC_ADDRESS,
            msg=f"Reply must source from interface 2's MAC. Got: {probe!r}",
        )
        self.assertEqual(
            probe.eth_dst,
            IFACE2__PEER__MAC_ADDRESS,
            msg=f"Reply dst MAC must be resolved via interface 2's own ARP cache. Got: {probe!r}",
        )

    def test__multi_interface__udp_send_to_iface2_subnet_egresses_iface2(self) -> None:
        """
        Ensure a stack-originated UDP datagram to a destination on the
        second interface's subnet egresses the second interface — the
        egress resolver picks the interface the FIB selects ('Route.oif'),
        the frame lands on interface 2's TX ring, and interface 1 emits
        nothing. This is the multi-homed-host originated-traffic payoff.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        """

        stack.egress_packet_handler(IFACE2__PEER__IP4_ADDRESS).send_udp_packet(
            ip__local_address=IFACE2__IP4_HOST.address,
            ip__remote_address=IFACE2__PEER__IP4_ADDRESS,
            udp__local_port=12345,
            udp__remote_port=53,
            udp__payload=b"query",
        )

        self.assertEqual(
            len(self._iface2.frames_tx),
            1,
            msg="A UDP datagram to interface 2's subnet must egress interface 2's TX ring.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="Interface 1 must emit nothing for a datagram routed out interface 2.",
        )
