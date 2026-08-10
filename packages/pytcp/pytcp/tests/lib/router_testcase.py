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
from net_proto import (
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageRedirect,
    Icmp4MessageTimeExceeded,
    Icmp6Assembler,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessagePacketTooBig,
    Icmp6MessageTimeExceeded,
    Icmp6Mld2MessageQuery,
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6NdMessageRedirect,
    Icmp6Type,
    IgmpAssembler,
    IgmpMessageQuery,
    IgmpMessageV2Leave,
    IgmpMessageV3Report,
    IgmpV3GroupRecord,
    IgmpVersion,
    Ip4OptionRouterAlert,
    Ip4Options,
    IpProto,
)
from net_proto.lib.enums import EtherType
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from net_proto.protocols.udp.udp__parser import UdpParser
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.stack import sysctl as sysctl_module
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
# if-2's link-local address — the RFC 4861 §4.5 mandated source for
# an ICMPv6 Redirect emitted out this interface.
ROUTER__IF2__IP6_LINK_LOCAL = Ip6IfAddr("fe80::2/64")
HOST_D__MAC = MacAddress("02:00:00:00:00:20")
HOST_D__IP4 = Ip4Address("10.0.2.20")
HOST_D__IP6 = Ip6Address("2001:db8:0:2::20")

# An on-link LAN-B host whose neighbor entry is a permanent MISS
# (seeded to None) — the fixture for the forward "no neighbor"
# path, where next-hop resolution fails and the datagram is queued
# pending resolution rather than emitted.
HOST_E__IP4 = Ip4Address("10.0.2.21")
HOST_E__IP6 = Ip6Address("2001:db8:0:2::21")

# An on-link LAN-B gateway (distinct from HOST_D) used as the
# next hop for the ICMP-Redirect hairpin tests: a route whose
# gateway is on the SAME interface the datagram arrives on makes
# the router forward it back out that interface (ingress ==
# egress) and advise the source of the better first hop.
LAN_B_GW__MAC = MacAddress("02:00:00:00:00:30")
LAN_B_GW__IP4 = Ip4Address("10.0.2.30")
LAN_B_GW__IP6 = Ip6Address("2001:db8:0:2::30")

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

        # if-2 = LAN-B (10.0.2.0/24 / 2001:db8:0:2::/64), HOST_D on-link
        # and resolvable; HOST_E on-link but a permanent neighbor miss.
        self.if2 = self._add_interface(
            mac_address=ROUTER__IF2__MAC,
            ip4_host=ROUTER__IF2__IP4,
            ip6_host=ROUTER__IF2__IP6,
            arp_entries={
                HOST_D__IP4: HOST_D__MAC,
                HOST_E__IP4: None,
                LAN_B_GW__IP4: LAN_B_GW__MAC,
            },
            nd_entries={
                HOST_D__IP6: HOST_D__MAC,
                HOST_E__IP6: None,
                LAN_B_GW__IP6: LAN_B_GW__MAC,
            },
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

        # Give if-2 a link-local address so the ICMPv6 Redirect path has
        # the RFC 4861 §4.5 mandated link-local source available.
        self.if2.handler._ip6_ifaddr.append(ROUTER__IF2__IP6_LINK_LOCAL)

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

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so a test that enabled forwarding does
        not leak the mutation into unrelated tests run in the same
        process.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _enable_forwarding(self) -> None:
        """
        Enable IPv4 and IPv6 forwarding stack-wide via the global
        master switches, turning the router-under-test into a
        forwarder on every interface.
        """

        sysctl_module.set("ip4.ip_forward", True)
        sysctl_module.set("ip6.all.forwarding", True)

    def _enable_igmp_querier(self, *ifaces: AddedInterface) -> dict[int, list[bytes]]:
        """
        Enable the IGMP querier role ('igmp.mc_forwarding') and bring it
        up on each named interface, returning the frames each interface
        emitted as a direct result (the first of the startup General
        Query burst). The test-harness interfaces are unnamed, so the
        knob's 'default' slot is set; only the interfaces whose querier
        is explicitly brought up here become queriers.
        """

        sysctl_module.set("igmp.default.mc_forwarding", True)

        # A querier receives competing election Queries on the all-systems
        # group 224.0.0.1 (address pre-seeded; admit its MAC here). The
        # all-IGMPv3-routers group 224.0.0.22 (Membership Reports) is
        # admitted receive-only by '_start_querier' itself.
        all_systems_mac = Ip4Address("224.0.0.1").multicast_mac

        before = {interface.ifindex: len(interface.frames_tx) for interface in self._interfaces}
        for iface in ifaces:
            if all_systems_mac not in iface.handler._mac_multicast:
                iface.handler._mac_multicast.append(all_systems_mac)
            iface.handler.refresh_igmp_querier()
        return {
            interface.ifindex: list(interface.frames_tx[before[interface.ifindex] :]) for interface in self._interfaces
        }

    def _advance_frames(self, *, ms: int) -> dict[int, list[bytes]]:
        """
        Advance the virtual clock by 'ms' and return, per interface
        index, the frames that interface emitted during the tick — the
        timer-driven analogue of '_drive_forward'.
        """

        before = {interface.ifindex: len(interface.frames_tx) for interface in self._interfaces}
        self._advance(ms=ms)
        return {
            interface.ifindex: list(interface.frames_tx[before[interface.ifindex] :]) for interface in self._interfaces
        }

    def _build_igmp_general_query(
        self,
        *,
        src_ip: Ip4Address,
        src_mac: MacAddress,
        qrv: int = 2,
        max_resp_code: int = 100,
        qqic: int = 125,
    ) -> bytes:
        """
        Build an inbound IGMPv3 General Query (group 0.0.0.0) from a
        competing querier — carried in Ethernet/IPv4 to the all-systems
        group 224.0.0.1 with the Router Alert option and TTL 1 — for the
        querier-election tests.
        """

        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=Ip4Address("224.0.0.1").multicast_mac,
            ethernet__payload=Ip4Assembler(
                ip4__src=src_ip,
                ip4__dst=Ip4Address("224.0.0.1"),
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=IgmpAssembler(
                    igmp__message=IgmpMessageQuery(
                        version=IgmpVersion.V3,
                        max_resp_code=max_resp_code,
                        group_address=Ip4Address(),
                        qrv=qrv,
                        qqic=qqic,
                    )
                ),
            ),
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _build_igmp_v2_leave(
        self,
        *,
        src_ip: Ip4Address,
        src_mac: MacAddress,
        group: Ip4Address,
    ) -> bytes:
        """
        Build an inbound IGMPv2 Leave Group for 'group' from a downstream
        host — carried in Ethernet/IPv4 to the all-routers group
        224.0.0.2 with the Router Alert option and TTL 1 — for the
        querier fast-leave tests.
        """

        all_routers = Ip4Address("224.0.0.2")
        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=all_routers.multicast_mac,
            ethernet__payload=Ip4Assembler(
                ip4__src=src_ip,
                ip4__dst=all_routers,
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=IgmpAssembler(igmp__message=IgmpMessageV2Leave(group_address=group)),
            ),
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _build_igmp_v3_report(
        self,
        *,
        src_ip: Ip4Address,
        src_mac: MacAddress,
        records: list[IgmpV3GroupRecord],
    ) -> bytes:
        """
        Build an inbound IGMPv3 Membership Report from a downstream host —
        carried in Ethernet/IPv4 to the all-IGMPv3-routers group
        224.0.0.22 with the Router Alert option and TTL 1 — for the
        querier membership-learning tests.
        """

        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=Ip4Address("224.0.0.22").multicast_mac,
            ethernet__payload=Ip4Assembler(
                ip4__src=src_ip,
                ip4__dst=Ip4Address("224.0.0.22"),
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=IgmpAssembler(igmp__message=IgmpMessageV3Report(records=records)),
            ),
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _assert_igmp_general_query(self, frame: bytes, /, *, source: Ip4Address) -> IgmpMessageQuery:
        """
        Assert that 'frame' is an IGMPv3 General Query emitted by the
        querier — carried in IPv4 to the all-systems group 224.0.0.1
        with TTL 1 (RFC 3376 §4), sourced from 'source', with the group
        address 0.0.0.0 and no sources — and return the decoded Query
        for any further per-field assertions.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip4Parser(packet_rx)

        self.assertEqual(
            packet_rx.ip4.dst,
            Ip4Address("224.0.0.1"),
            msg=f"General Query must be sent to the all-systems group 224.0.0.1; got {packet_rx.ip4.dst}.",
        )
        self.assertEqual(
            packet_rx.ip4.ttl,
            1,
            msg=f"General Query must be sent with TTL 1; got {packet_rx.ip4.ttl}.",
        )
        self.assertEqual(
            packet_rx.ip4.src,
            source,
            msg=f"General Query must be sourced from {source}; got {packet_rx.ip4.src}.",
        )

        IgmpParser(packet_rx)
        message = packet_rx.igmp.message
        self.assertIsInstance(
            message,
            IgmpMessageQuery,
            msg=f"Emitted IGMP message must be a Membership Query; got {type(message).__name__}.",
        )
        assert isinstance(message, IgmpMessageQuery)
        self.assertTrue(
            message.is_general_query,
            msg="Emitted Query must be a General Query (group 0.0.0.0, no sources).",
        )
        return message

    def _assert_igmp_group_specific_query(self, frame: bytes, /, *, group: Ip4Address) -> IgmpMessageQuery:
        """
        Assert that 'frame' is an IGMPv3 Group-Specific Query for 'group'
        — carried in IPv4 to the group address itself with TTL 1 (RFC
        3376 §4.1 / §6.4.2) — and return the decoded Query.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip4Parser(packet_rx)

        self.assertEqual(
            packet_rx.ip4.dst,
            group,
            msg=f"Group-Specific Query must be sent to the group {group}; got {packet_rx.ip4.dst}.",
        )
        self.assertEqual(
            packet_rx.ip4.ttl, 1, msg=f"Group-Specific Query must be sent with TTL 1; got {packet_rx.ip4.ttl}."
        )

        IgmpParser(packet_rx)
        message = packet_rx.igmp.message
        self.assertIsInstance(
            message,
            IgmpMessageQuery,
            msg=f"Emitted IGMP message must be a Membership Query; got {type(message).__name__}.",
        )
        assert isinstance(message, IgmpMessageQuery)
        self.assertEqual(
            message.group_address,
            group,
            msg=f"Group-Specific Query must carry group {group}; got {message.group_address}.",
        )
        self.assertFalse(
            message.is_general_query,
            msg="A Group-Specific Query must not report as a General Query.",
        )
        return message

    def _enable_mld_querier(self, *ifaces: AddedInterface) -> dict[int, list[bytes]]:
        """
        Enable the MLD querier role ('mld.mc_forwarding') and bring it up
        on each named interface, returning the frames each emitted (the
        first startup General Query). The IPv6 analogue of
        '_enable_igmp_querier'; admits the all-nodes multicast MAC so
        election Queries are received (the all-MLDv2-routers group for
        Reports is admitted receive-only by '_start_querier').
        """

        sysctl_module.set("mld.default.mc_forwarding", True)
        all_nodes_mac = Ip6Address("ff02::1").multicast_mac

        before = {interface.ifindex: len(interface.frames_tx) for interface in self._interfaces}
        for iface in ifaces:
            if all_nodes_mac not in iface.handler._mac_multicast:
                iface.handler._mac_multicast.append(all_nodes_mac)
            iface.handler.refresh_mld_querier()
        return {
            interface.ifindex: list(interface.frames_tx[before[interface.ifindex] :]) for interface in self._interfaces
        }

    def _build_mld2_general_query(
        self,
        *,
        src_ip: Ip6Address,
        src_mac: MacAddress,
        qrv: int = 2,
        max_resp_code: int = 10000,
        qqic: int = 125,
    ) -> bytes:
        """
        Build an inbound MLDv2 General Query (multicast address ::) from a
        competing querier — carried in Ethernet/IPv6 to the all-nodes
        group ff02::1 with Hop Limit 1 — for the querier-election tests.
        """

        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=Ip6Address("ff02::1").multicast_mac,
            ethernet__payload=Ip6Assembler(
                ip6__src=src_ip,
                ip6__dst=Ip6Address("ff02::1"),
                ip6__hop=1,
                ip6__payload=Icmp6Assembler(
                    icmp6__message=Icmp6Mld2MessageQuery(
                        maximum_response_code=max_resp_code,
                        multicast_address=Ip6Address(),
                        qrv=qrv,
                        qqic=qqic,
                    )
                ),
            ),
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _build_mld2_report(
        self,
        *,
        src_ip: Ip6Address,
        src_mac: MacAddress,
        records: list[Icmp6Mld2MulticastAddressRecord],
    ) -> bytes:
        """
        Build an inbound MLDv2 Report from a downstream host — carried in
        Ethernet/IPv6 to the all-MLDv2-routers group ff02::16 with Hop
        Limit 1 — for the querier membership-learning tests.
        """

        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=Ip6Address("ff02::16").multicast_mac,
            ethernet__payload=Ip6Assembler(
                ip6__src=src_ip,
                ip6__dst=Ip6Address("ff02::16"),
                ip6__hop=1,
                ip6__payload=Icmp6Assembler(icmp6__message=Icmp6Mld2MessageReport(records=records)),
            ),
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _assert_mld_general_query(self, frame: bytes, /, *, source: Ip6Address) -> Icmp6Mld2MessageQuery:
        """
        Assert that 'frame' is an MLDv2 General Query emitted by the
        querier — carried in IPv6 to the all-nodes group ff02::1 with Hop
        Limit 1 (RFC 3810 §5.1), sourced from 'source', with the
        unspecified multicast address (::) — and return the decoded Query.
        """

        probe = self._parse_tx_icmp6(frame)

        self.assertEqual(
            probe.icmp_type,
            int(Icmp6Type.MULTICAST_LISTENER_QUERY),
            msg=f"Emitted ICMPv6 message must be a Multicast Listener Query; got type {probe.icmp_type}.",
        )
        self.assertEqual(
            probe.ip_dst,
            Ip6Address("ff02::1"),
            msg=f"General Query must be sent to the all-nodes group ff02::1; got {probe.ip_dst}.",
        )
        self.assertEqual(
            probe.ip_hop,
            1,
            msg=f"General Query must be sent with Hop Limit 1; got {probe.ip_hop}.",
        )
        self.assertEqual(
            probe.ip_src,
            source,
            msg=f"General Query must be sourced from {source}; got {probe.ip_src}.",
        )
        self.assertIsInstance(
            probe.message,
            Icmp6Mld2MessageQuery,
            msg=f"Emitted message must be an MLDv2 Query; got {type(probe.message).__name__}.",
        )
        assert isinstance(probe.message, Icmp6Mld2MessageQuery)
        self.assertTrue(
            probe.message.multicast_address.is_unspecified,
            msg="Emitted Query must be a General Query (multicast address ::).",
        )
        return probe.message

    def _assert_single_egress(self, emitted: dict[int, list[bytes]], /, *, egress: AddedInterface) -> bytes:
        """
        Assert that '_drive_forward' emitted exactly one frame on
        'egress' and nothing on any other interface, and return that
        egress frame for further decoding.
        """

        for ifindex, frames in emitted.items():
            expected = 1 if ifindex == egress.ifindex else 0
            self.assertEqual(
                len(frames),
                expected,
                msg=(
                    f"Expected {expected} frame(s) on ifindex {ifindex} "
                    f"(egress is ifindex {egress.ifindex}); got {len(frames)}: {frames!r}"
                ),
            )
        return emitted[egress.ifindex][0]

    def _assert_forwarded_ip4(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        egress: AddedInterface,
        src_ip: Ip4Address,
        dst_ip: Ip4Address,
        ttl_out: int,
        next_hop_mac: MacAddress,
        payload: bytes,
    ) -> None:
        """
        Assert that the datagram was forwarded out 'egress' toward
        'next_hop_mac': Ethernet dst is the next-hop MAC and src is the
        egress interface's own MAC; the IPv4 source / destination are
        preserved; the TTL is 'ttl_out' (ttl_in - 1); the header
        checksum is valid; and the UDP payload is byte-identical.
        """

        frame = self._assert_single_egress(emitted, egress=egress)

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        self.assertEqual(
            packet_rx.ethernet.dst,
            next_hop_mac,
            msg=f"Forwarded frame Ethernet dst must be the next-hop MAC {next_hop_mac}.",
        )
        self.assertEqual(
            packet_rx.ethernet.src,
            egress.handler._mac_unicast,
            msg="Forwarded frame Ethernet src must be the egress interface's own MAC.",
        )
        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.IP4,
            msg="Forwarded frame Ethernet type must be IPv4.",
        )

        Ip4Parser(packet_rx)
        self.assertEqual(
            packet_rx.ip4.src,
            src_ip,
            msg="Forwarded IPv4 source must be preserved.",
        )
        self.assertEqual(
            packet_rx.ip4.dst,
            dst_ip,
            msg="Forwarded IPv4 destination must be preserved.",
        )
        self.assertEqual(
            packet_rx.ip4.ttl,
            ttl_out,
            msg=f"Forwarded IPv4 TTL must be decremented to {ttl_out}.",
        )
        self.assertEqual(
            inet_cksum(memoryview(bytes(packet_rx.ip4.packet_bytes))[: packet_rx.ip4.hlen]),
            0,
            msg="Forwarded IPv4 header checksum must be valid (sums to zero).",
        )

        UdpParser(packet_rx)
        self.assertEqual(
            bytes(packet_rx.udp.payload),
            payload,
            msg="Forwarded UDP payload must be byte-identical.",
        )

    def _assert_forwarded_ip6(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        egress: AddedInterface,
        src_ip: Ip6Address,
        dst_ip: Ip6Address,
        hop_out: int,
        next_hop_mac: MacAddress,
        payload: bytes,
    ) -> None:
        """
        Assert that the datagram was forwarded out 'egress' toward
        'next_hop_mac': Ethernet dst is the next-hop MAC and src is the
        egress interface's own MAC; the IPv6 source / destination are
        preserved; the Hop-Limit is 'hop_out' (hop_in - 1); and the UDP
        payload is byte-identical.
        """

        frame = self._assert_single_egress(emitted, egress=egress)

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        self.assertEqual(
            packet_rx.ethernet.dst,
            next_hop_mac,
            msg=f"Forwarded frame Ethernet dst must be the next-hop MAC {next_hop_mac}.",
        )
        self.assertEqual(
            packet_rx.ethernet.src,
            egress.handler._mac_unicast,
            msg="Forwarded frame Ethernet src must be the egress interface's own MAC.",
        )
        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.IP6,
            msg="Forwarded frame Ethernet type must be IPv6.",
        )

        Ip6Parser(packet_rx)
        self.assertEqual(
            packet_rx.ip6.src,
            src_ip,
            msg="Forwarded IPv6 source must be preserved.",
        )
        self.assertEqual(
            packet_rx.ip6.dst,
            dst_ip,
            msg="Forwarded IPv6 destination must be preserved.",
        )
        self.assertEqual(
            packet_rx.ip6.hop,
            hop_out,
            msg=f"Forwarded IPv6 Hop-Limit must be decremented to {hop_out}.",
        )

        UdpParser(packet_rx)
        self.assertEqual(
            bytes(packet_rx.udp.payload),
            payload,
            msg="Forwarded UDP payload must be byte-identical.",
        )

    def _assert_icmp4_error(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        ingress: AddedInterface,
        icmp_type: int,
        icmp_code: int,
        to_ip: Ip4Address,
        mtu: int | None = None,
    ) -> None:
        """
        Assert that the only frame emitted is an ICMPv4 error of
        '(icmp_type, icmp_code)' sent back to 'to_ip' out the ingress
        interface, embedding the offending datagram. When 'mtu' is given
        (Fragmentation Needed), assert the next-hop MTU field carries it.
        """

        frame = self._assert_single_egress(emitted, egress=ingress)
        probe = self._parse_tx_icmp4(frame)
        self.assertEqual(probe.icmp_type, icmp_type, msg="Unexpected ICMPv4 error type.")
        self.assertEqual(probe.icmp_code, icmp_code, msg="Unexpected ICMPv4 error code.")
        self.assertEqual(probe.ip_dst, to_ip, msg="ICMPv4 error must be sent back to the datagram source.")
        message = probe.message
        self.assertIsInstance(
            message,
            (Icmp4MessageDestinationUnreachable, Icmp4MessageTimeExceeded),
            msg="Forward ICMPv4 error must be a Destination Unreachable or Time Exceeded.",
        )
        assert isinstance(message, (Icmp4MessageDestinationUnreachable, Icmp4MessageTimeExceeded))
        self.assertGreater(
            len(message.data),
            0,
            msg="ICMPv4 error must embed the offending datagram.",
        )
        if mtu is not None:
            self.assertEqual(
                probe.icmp_mtu,
                mtu,
                msg="ICMPv4 Fragmentation Needed must carry the egress MTU as the next-hop MTU.",
            )

    def _assert_icmp6_packet_too_big(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        ingress: AddedInterface,
        mtu: int,
        to_ip: Ip6Address,
    ) -> None:
        """
        Assert that the only frame emitted is an ICMPv6 Packet Too Big
        (Type 2) carrying 'mtu' as the next-hop MTU, sent back to 'to_ip'
        out the ingress interface, embedding the offending datagram.
        """

        frame = self._assert_single_egress(emitted, egress=ingress)
        probe = self._parse_tx_icmp6(frame)
        self.assertEqual(probe.icmp_type, 2, msg="Unexpected ICMPv6 error type (expected Packet Too Big).")
        message = probe.message
        self.assertIsInstance(
            message,
            Icmp6MessagePacketTooBig,
            msg="Forward ICMPv6 oversize error must be a Packet Too Big.",
        )
        assert isinstance(message, Icmp6MessagePacketTooBig)
        self.assertEqual(probe.ip_dst, to_ip, msg="ICMPv6 Packet Too Big must be sent back to the datagram source.")
        self.assertEqual(message.mtu, mtu, msg="ICMPv6 Packet Too Big must carry the egress MTU.")
        self.assertGreater(len(message.data), 0, msg="ICMPv6 Packet Too Big must embed the offending datagram.")

    def _assert_forwarded_fragments_ip4(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        egress: AddedInterface,
        src_ip: Ip4Address,
        dst_ip: Ip4Address,
        ttl_out: int,
        next_hop_mac: MacAddress,
        payload: bytes,
        mtu: int,
    ) -> None:
        """
        Assert that the datagram was fragmented to 'mtu' and forwarded
        out 'egress' toward 'next_hop_mac' as two or more fragments,
        nothing on any other interface: every fragment fits the MTU,
        preserves the IPv4 source / destination / Identification, carries
        'ttl_out' (ttl_in - 1), sets MF=1 on all but the last, has
        contiguous offsets, and — reassembled — reproduces the original
        UDP datagram whose payload is 'payload' byte-for-byte.
        """

        for ifindex, frames in emitted.items():
            if ifindex == egress.ifindex:
                self.assertGreater(len(frames), 1, msg="Fragmented forward must emit two or more fragments.")
            else:
                self.assertEqual(frames, [], msg=f"No fragment must leave ifindex {ifindex}.")

        frames = emitted[egress.ifindex]
        reassembled = bytearray()
        expected_offset = 0
        fragment_id: int | None = None
        for index, frame in enumerate(frames):
            packet_rx = PacketRx(frame)
            EthernetParser(packet_rx)
            self.assertEqual(
                packet_rx.ethernet.dst, next_hop_mac, msg="Fragment Ethernet dst must be the next-hop MAC."
            )
            self.assertIs(packet_rx.ethernet.type, EtherType.IP4, msg="Fragment Ethernet type must be IPv4.")
            # Frame length minus the 14-byte Ethernet header is the IPv4
            # datagram length, which must fit the egress MTU.
            self.assertLessEqual(len(frame) - 14, mtu, msg="Every fragment must fit the egress MTU.")
            Ip4Parser(packet_rx)
            self.assertEqual(packet_rx.ip4.src, src_ip, msg="Fragment IPv4 source must be preserved.")
            self.assertEqual(packet_rx.ip4.dst, dst_ip, msg="Fragment IPv4 destination must be preserved.")
            self.assertEqual(packet_rx.ip4.ttl, ttl_out, msg=f"Fragment TTL must be {ttl_out}.")
            self.assertEqual(packet_rx.ip4.offset, expected_offset, msg="Fragment offsets must be contiguous.")
            is_last = index == len(frames) - 1
            self.assertEqual(
                packet_rx.ip4.flag_mf,
                not is_last,
                msg="Every fragment but the last must set MF=1; the last must clear it.",
            )
            if fragment_id is None:
                fragment_id = packet_rx.ip4.id
            self.assertEqual(
                packet_rx.ip4.id,
                fragment_id,
                msg="All fragments must share the original datagram's Identification.",
            )
            reassembled += bytes(packet_rx.ip4.payload_bytes)
            expected_offset += len(packet_rx.ip4.payload_bytes)

        # The reassembled IPv4 payload is the original UDP datagram: an
        # 8-byte UDP header followed by the byte-identical payload.
        self.assertEqual(
            len(reassembled),
            8 + len(payload),
            msg="Reassembled fragments must reproduce exactly one UDP datagram (8-byte header + payload).",
        )
        self.assertEqual(
            bytes(reassembled[8:]),
            payload,
            msg="Reassembled UDP payload must be byte-identical to the original.",
        )

    def _assert_icmp6_error(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        ingress: AddedInterface,
        icmp_type: int,
        icmp_code: int,
        to_ip: Ip6Address,
    ) -> None:
        """
        Assert that the only frame emitted is an ICMPv6 error of
        '(icmp_type, icmp_code)' sent back to 'to_ip' out the ingress
        interface, embedding the offending datagram.
        """

        frame = self._assert_single_egress(emitted, egress=ingress)
        probe = self._parse_tx_icmp6(frame)
        self.assertEqual(probe.icmp_type, icmp_type, msg="Unexpected ICMPv6 error type.")
        self.assertEqual(probe.icmp_code, icmp_code, msg="Unexpected ICMPv6 error code.")
        self.assertEqual(probe.ip_dst, to_ip, msg="ICMPv6 error must be sent back to the datagram source.")
        message = probe.message
        self.assertIsInstance(
            message,
            (Icmp6MessageDestinationUnreachable, Icmp6MessageTimeExceeded),
            msg="Forward ICMPv6 error must be a Destination Unreachable or Time Exceeded.",
        )
        assert isinstance(message, (Icmp6MessageDestinationUnreachable, Icmp6MessageTimeExceeded))
        self.assertGreater(
            len(message.data),
            0,
            msg="ICMPv6 error must embed the offending datagram.",
        )

    def _assert_redirect_and_forward_ip4(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        iface: AddedInterface,
        src_ip: Ip4Address,
        dst_ip: Ip4Address,
        gateway: Ip4Address,
        next_hop_mac: MacAddress,
        ttl_out: int,
        payload: bytes,
    ) -> None:
        """
        Assert that a hairpin forward emitted exactly two frames on
        'iface' (nothing elsewhere): an ICMPv4 Redirect (Type 5, Code 1 —
        host) back to 'src_ip' advertising 'gateway' as the better first
        hop, AND the triggering datagram still forwarded toward
        'next_hop_mac' with the TTL decremented and payload preserved.
        """

        for ifindex, frames in emitted.items():
            expected = 2 if ifindex == iface.ifindex else 0
            self.assertEqual(
                len(frames),
                expected,
                msg=f"Expected {expected} frame(s) on ifindex {ifindex}; got {len(frames)}: {frames!r}",
            )

        redirect_frame: bytes | None = None
        forward_frame: bytes | None = None
        for frame in emitted[iface.ifindex]:
            packet_rx = PacketRx(frame)
            EthernetParser(packet_rx)
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is IpProto.ICMP4:
                redirect_frame = frame
            else:
                forward_frame = frame

        self.assertIsNotNone(redirect_frame, msg="A hairpin forward must emit an ICMPv4 Redirect.")
        self.assertIsNotNone(forward_frame, msg="A hairpin forward must still forward the triggering datagram.")
        assert redirect_frame is not None and forward_frame is not None

        probe = self._parse_tx_icmp4(redirect_frame)
        self.assertEqual(probe.icmp_type, 5, msg="Redirect must be ICMPv4 type 5.")
        self.assertEqual(probe.icmp_code, 1, msg="Redirect must use the host code (1).")
        self.assertEqual(probe.ip_dst, src_ip, msg="Redirect must be sent back to the datagram source.")
        message = probe.message
        self.assertIsInstance(message, Icmp4MessageRedirect, msg="Emitted message must be an ICMPv4 Redirect.")
        assert isinstance(message, Icmp4MessageRedirect)
        self.assertEqual(message.gateway, gateway, msg="Redirect must advertise the better first hop as gateway.")

        forward_rx = PacketRx(forward_frame)
        EthernetParser(forward_rx)
        self.assertEqual(forward_rx.ethernet.dst, next_hop_mac, msg="Forwarded frame must go to the next-hop MAC.")
        Ip4Parser(forward_rx)
        self.assertEqual(forward_rx.ip4.dst, dst_ip, msg="Forwarded IPv4 destination must be preserved.")
        self.assertEqual(forward_rx.ip4.ttl, ttl_out, msg=f"Forwarded IPv4 TTL must be {ttl_out}.")
        UdpParser(forward_rx)
        self.assertEqual(bytes(forward_rx.udp.payload), payload, msg="Forwarded UDP payload must be preserved.")

    def _assert_redirect_and_forward_ip6(
        self,
        emitted: dict[int, list[bytes]],
        /,
        *,
        iface: AddedInterface,
        src_ip: Ip6Address,
        dst_ip: Ip6Address,
        target: Ip6Address,
        next_hop_mac: MacAddress,
        hop_out: int,
        payload: bytes,
    ) -> None:
        """
        Assert that a hairpin forward emitted exactly two frames on
        'iface' (nothing elsewhere): an ICMPv6 ND Redirect back to
        'src_ip' advertising 'target' as the better first hop for
        'dst_ip', AND the triggering datagram still forwarded toward
        'next_hop_mac' with the Hop-Limit decremented and payload
        preserved.
        """

        for ifindex, frames in emitted.items():
            expected = 2 if ifindex == iface.ifindex else 0
            self.assertEqual(
                len(frames),
                expected,
                msg=f"Expected {expected} frame(s) on ifindex {ifindex}; got {len(frames)}: {frames!r}",
            )

        redirect_frame: bytes | None = None
        forward_frame: bytes | None = None
        for frame in emitted[iface.ifindex]:
            packet_rx = PacketRx(frame)
            EthernetParser(packet_rx)
            Ip6Parser(packet_rx)
            if packet_rx.ip6.next is IpProto.ICMP6:
                redirect_frame = frame
            else:
                forward_frame = frame

        self.assertIsNotNone(redirect_frame, msg="A hairpin forward must emit an ICMPv6 ND Redirect.")
        self.assertIsNotNone(forward_frame, msg="A hairpin forward must still forward the triggering datagram.")
        assert redirect_frame is not None and forward_frame is not None

        probe = self._parse_tx_icmp6(redirect_frame)
        self.assertEqual(probe.icmp_type, 137, msg="Redirect must be ICMPv6 type 137 (ND Redirect).")
        self.assertEqual(probe.ip_dst, src_ip, msg="Redirect must be sent back to the datagram source.")
        self.assertTrue(probe.ip_src.is_link_local, msg="ICMPv6 Redirect source must be link-local (RFC 4861 §4.5).")
        message = probe.message
        self.assertIsInstance(message, Icmp6NdMessageRedirect, msg="Emitted message must be an ICMPv6 ND Redirect.")
        assert isinstance(message, Icmp6NdMessageRedirect)
        self.assertEqual(message.target_address, target, msg="Redirect target must be the better first hop.")
        self.assertEqual(message.destination_address, dst_ip, msg="Redirect destination must be the original dst.")

        forward_rx = PacketRx(forward_frame)
        EthernetParser(forward_rx)
        self.assertEqual(forward_rx.ethernet.dst, next_hop_mac, msg="Forwarded frame must go to the next-hop MAC.")
        Ip6Parser(forward_rx)
        self.assertEqual(forward_rx.ip6.dst, dst_ip, msg="Forwarded IPv6 destination must be preserved.")
        self.assertEqual(forward_rx.ip6.hop, hop_out, msg=f"Forwarded IPv6 Hop-Limit must be {hop_out}.")
        UdpParser(forward_rx)
        self.assertEqual(bytes(forward_rx.udp.payload), payload, msg="Forwarded UDP payload must be preserved.")

    def _build_transit_ip4(
        self,
        *,
        ingress: AddedInterface,
        src_mac: MacAddress,
        src_ip: Ip4Address,
        dst_ip: Ip4Address,
        ttl: int = 64,
        df: bool = False,
        payload: bytes = b"router-forward-test",
    ) -> bytes:
        """
        Build an Ethernet/IPv4/UDP datagram arriving at 'ingress' (its
        Ethernet destination is the ingress interface's own unicast MAC)
        from an on-link source, addressed to an IPv4 destination that is
        not one of the router's own addresses — i.e. a transit datagram.
        'df' sets the Don't-Fragment flag (for the transit-PMTU tests).
        """

        udp = UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=payload)
        ip4 = Ip4Assembler(ip4__src=src_ip, ip4__dst=dst_ip, ip4__ttl=ttl, ip4__flag_df=df, ip4__payload=udp)
        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=ingress.handler._mac_unicast,
            ethernet__payload=ip4,
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _build_transit_multicast_ip4(
        self,
        *,
        src_mac: MacAddress,
        src_ip: Ip4Address,
        group: Ip4Address,
        ttl: int = 10,
        payload: bytes = b"mcast-forward-test",
    ) -> bytes:
        """
        Build an Ethernet/IPv4/UDP transit multicast datagram addressed
        to 'group' (its Ethernet destination is the group's own multicast
        MAC) from an off-link source — the datagram a multicast router
        replicates to downstream listeners.
        """

        udp = UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=payload)
        ip4 = Ip4Assembler(ip4__src=src_ip, ip4__dst=group, ip4__ttl=ttl, ip4__payload=udp)
        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=group.multicast_mac,
            ethernet__payload=ip4,
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _build_transit_multicast_ip6(
        self,
        *,
        src_mac: MacAddress,
        src_ip: Ip6Address,
        group: Ip6Address,
        hop: int = 10,
        payload: bytes = b"mcast-forward-test",
    ) -> bytes:
        """
        Build an Ethernet/IPv6/UDP transit multicast datagram addressed
        to 'group' (its Ethernet destination is the group's own multicast
        MAC) from an off-link source — the datagram a multicast router
        replicates to downstream listeners.
        """

        udp = UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=payload)
        ip6 = Ip6Assembler(ip6__src=src_ip, ip6__dst=group, ip6__hop=hop, ip6__payload=udp)
        eth = EthernetAssembler(
            ethernet__src=src_mac,
            ethernet__dst=group.multicast_mac,
            ethernet__payload=ip6,
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

    def _assert_iface_packet_stats_rx(self, iface: AddedInterface, /, **fields: int) -> None:
        """
        Assert an exact match of the RX packet-stats on a specific
        interface — every counter not named in 'fields' must be zero.
        The per-interface analogue of 'IcmpTestCase._assert_packet_stats_rx'
        (which pins the boot interface); needed when a test drives an
        inbound frame into if2 / if3 rather than the boot interface.
        """

        self.assertEqual(
            iface.handler.packet_stats_rx,
            PacketStatsRx(**fields),
            msg=(
                f"Unexpected packet_stats_rx on ifindex {iface.ifindex} (exact match "
                f"required, unspecified counters must be zero). Got: {iface.handler.packet_stats_rx!r}"
            ),
        )

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
