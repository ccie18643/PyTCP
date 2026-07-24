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
This module contains the 'RouterTestCase' base class for the Phase-2
router forwarding-plane integration tests. It layers a canonical
three-interface "router-under-test" topology on top of 'IcmpTestCase'
— the boot interface as LAN-A, plus a LAN-B interface and an upstream
interface added via the reusable '_add_interface' affordance — with a
default route via the upstream gateway. Three interfaces is the
smallest topology that exercises egress *selection* (the FIB must
choose between LAN-B and the upstream egress) rather than egress
inevitability, which a two-interface topology cannot test.

pytcp/tests/lib/router_testcase.py

ver 3.0.9
"""

from typing import override

from net_addr import (
    Buffer,
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
)
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import AddedInterface

# The boot interface (ifindex 1) is LAN-A — 10.0.1.0/24 / 2001:db8:0:1::/64
# — reused from 'NetworkTestCase' with its own ARP / ND fixture tables
# (HOST_A resolves, HOST_B does not). The router's LAN-A address is the
# harness 'STACK__IP4_HOST' (10.0.1.7); its on-link peer is
# 'HOST_A__IP4_ADDRESS' (10.0.1.91).

# if-2 — LAN-B, a distinct directly-connected subnet.
ROUTER__IF2__MAC = MacAddress("02:00:00:00:00:02")
ROUTER__IF2__IP4 = Ip4IfAddr("10.0.2.1/24")
ROUTER__IF2__IP6 = Ip6IfAddr("2001:db8:0:2::1/64")
HOST_D__MAC = MacAddress("02:00:00:00:00:20")
HOST_D__IP4 = Ip4Address("10.0.2.20")
HOST_D__IP6 = Ip6Address("2001:db8:0:2::20")

# if-3 — the upstream interface carrying the default route.
ROUTER__IF3__MAC = MacAddress("02:00:00:00:00:03")
ROUTER__IF3__IP4 = Ip4IfAddr("203.0.113.1/24")
ROUTER__IF3__IP6 = Ip6IfAddr("2001:db8:0:3::1/64")
UPSTREAM_GW__MAC = MacAddress("02:00:00:00:00:fe")
UPSTREAM_GW__IP4 = Ip4Address("203.0.113.254")
UPSTREAM_GW__IP6 = Ip6Address("2001:db8:0:3::fe")

# An off-net ("internet") destination reachable only via the default
# route — covered by neither LAN-A, LAN-B, nor the upstream subnet, so
# the FIB must resolve it through the default route out if-3.
INTERNET__IP4 = Ip4Address("198.51.100.10")
INTERNET__IP6 = Ip6Address("2001:db8:0:9::10")


class RouterTestCase(IcmpTestCase):
    """
    Base class for the router forwarding-plane integration tests.

    Adds the canonical three-interface router topology on top of the
    ICMP harness: the boot interface (if-1 / LAN-A), plus if-2 (LAN-B)
    and if-3 (upstream) installed via '_add_interface', with a default
    route via the upstream gateway. The three interface handles are
    exposed as 'if1' / 'if2' / 'if3' 'AddedInterface's so tests drive an
    inbound frame into a chosen ingress interface and inspect the frames
    every interface emits in response.

    Forwarding is host-disabled by default: without the 'ip_forward'
    knob (which lands with milestone M1) an inbound datagram not
    addressed to us is dropped, matching the current host-mode baseline
    these tests pin. The forwarding-enable helper arrives with M1.
    """

    if1: AddedInterface
    if2: AddedInterface
    if3: AddedInterface
    _interfaces: list[AddedInterface]

    @override
    def setUp(self) -> None:
        """
        Build the canonical three-interface router topology on top of the
        ICMP harness.
        """

        super().setUp()

        # if-1 = boot interface (LAN-A), reusing its fixture ARP / ND
        # tables. Wrapped in an 'AddedInterface' so all three interfaces
        # share one drive / capture surface.
        self.if1 = AddedInterface(handler=self._packet_handler, frames_tx=self._frames_tx)

        # if-2 = LAN-B (10.0.2.0/24 / 2001:db8:0:2::/64), HOST_D on-link.
        self.if2 = self._add_interface(
            mac_address=ROUTER__IF2__MAC,
            ip4_host=ROUTER__IF2__IP4,
            ip6_host=ROUTER__IF2__IP6,
            arp_entries={HOST_D__IP4: HOST_D__MAC},
            nd_entries={HOST_D__IP6: HOST_D__MAC},
        )

        # if-3 = upstream (203.0.113.0/24 / 2001:db8:0:3::/64), the
        # default-route egress toward UPSTREAM_GW.
        self.if3 = self._add_interface(
            mac_address=ROUTER__IF3__MAC,
            ip4_host=ROUTER__IF3__IP4,
            ip6_host=ROUTER__IF3__IP6,
            arp_entries={UPSTREAM_GW__IP4: UPSTREAM_GW__MAC},
            nd_entries={UPSTREAM_GW__IP6: UPSTREAM_GW__MAC},
        )

        self._interfaces = [self.if1, self.if2, self.if3]

        # Default routes via the upstream gateway on if-3. 'super().setUp()'
        # (mock__init) rebuilt both FIBs empty, so these are the only
        # explicit routes; the per-LAN connected routes are synthesized
        # from each interface's assigned address at lookup time.
        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=UPSTREAM_GW__IP4,
                oif=self.if3.ifindex,
                protocol=RouteProtocol.STATIC,
            )
        )
        stack.ip6_fib.add(
            route=Route(
                destination=Ip6Network("::/0"),
                gateway=UPSTREAM_GW__IP6,
                oif=self.if3.ifindex,
                protocol=RouteProtocol.STATIC,
            )
        )

    def _build_transit_ip4(
        self,
        *,
        ingress: AddedInterface,
        src_mac: MacAddress,
        src_ip: Ip4Address,
        dst_ip: Ip4Address,
        ttl: int = 64,
        payload: bytes = b"router-forward-test",
    ) -> bytes:
        """
        Build an Ethernet/IPv4/UDP datagram arriving at 'ingress' (its
        Ethernet destination is the ingress interface's own unicast MAC)
        from an on-link source, addressed to an IPv4 destination that is
        not one of the router's own addresses — i.e. a transit datagram.
        """

        udp = UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=payload)
        ip4 = Ip4Assembler(ip4__src=src_ip, ip4__dst=dst_ip, ip4__ttl=ttl, ip4__payload=udp)
        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=ingress.handler._mac_unicast,
            ethernet__payload=ip4,
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _build_transit_ip6(
        self,
        *,
        ingress: AddedInterface,
        src_mac: MacAddress,
        src_ip: Ip6Address,
        dst_ip: Ip6Address,
        hop: int = 64,
        payload: bytes = b"router-forward-test",
    ) -> bytes:
        """
        Build an Ethernet/IPv6/UDP datagram arriving at 'ingress' from an
        on-link source, addressed to an IPv6 destination that is not one
        of the router's own addresses — i.e. a transit datagram.
        """

        udp = UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=payload)
        ip6 = Ip6Assembler(ip6__src=src_ip, ip6__dst=dst_ip, ip6__hop=hop, ip6__payload=udp)
        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=ingress.handler._mac_unicast,
            ethernet__payload=ip6,
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _drive_forward(self, *, ingress: AddedInterface, frame: bytes) -> dict[int, list[bytes]]:
        """
        Feed 'frame' into the 'ingress' interface and return, per
        interface index, the frames that interface emitted as a direct
        result. A forwarded datagram appears under the egress interface's
        ifindex; a dropped one appears nowhere.
        """

        before = {interface.ifindex: len(interface.frames_tx) for interface in self._interfaces}
        ingress.handler._phrx_ethernet(PacketRx(frame))
        return {
            interface.ifindex: list(interface.frames_tx[before[interface.ifindex] :]) for interface in self._interfaces
        }

    def _assert_no_forward(self, emitted: dict[int, list[bytes]], /) -> None:
        """
        Assert that a '_drive_forward' produced no frame on any interface
        — the drop path (host does not forward, or a forward-plane drop).
        """

        for ifindex, frames in emitted.items():
            self.assertEqual(
                frames,
                [],
                msg=f"Expected no forwarded frame on ifindex {ifindex}; got {len(frames)}: {frames!r}",
            )
