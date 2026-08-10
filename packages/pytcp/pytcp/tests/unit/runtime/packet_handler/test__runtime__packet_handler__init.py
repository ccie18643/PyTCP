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
This module contains unit tests for the 'PacketHandler' base classes.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__init.py

ver 3.0.10
"""

import threading
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr, MacAddress
from net_proto import EtherType
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.tx_ring import TxRing

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4IfAddr("10.0.1.7/24")
STACK__IP6_HOST = Ip6IfAddr("2001:db8:0:1::7/64")


def _build_l2_handler() -> PacketHandlerL2:
    """
    Build a 'PacketHandlerL2' with IPv4/IPv6 addressing disabled so
    the constructor does not spawn DHCP / ND discovery threads.
    """

    return PacketHandlerL2(
        mac_address=STACK__MAC_UNICAST,
        interface_mtu=1500,
        ip4_support=False,
        ip6_support=False,
    )


def _build_l3_handler() -> PacketHandlerL3:
    """
    Build a 'PacketHandlerL3' with IPv4/IPv6 addressing disabled.
    """

    return PacketHandlerL3(
        interface_mtu=1500,
        ip4_support=False,
        ip6_support=False,
    )


class TestPacketHandlerBaseConstruction(TestCase):
    """
    The 'PacketHandler' __init__ invariants tests.
    """

    def test__stack__packet_handler__init__empty_defaults(self) -> None:
        """
        Ensure the base constructor creates empty host / candidate /
        multicast lists and a zeroed IPv4 IP-id counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()

        self.assertIsInstance(h._packet_stats_rx, PacketStatsRx)
        self.assertIsInstance(h._packet_stats_tx, PacketStatsTx)
        self.assertEqual(h._ip4_ifaddr, [])
        self.assertEqual(h._ip6_ifaddr, [])
        self.assertEqual(h._ip4_ifaddr_candidate, [])
        self.assertEqual(h._ip6_ifaddr_candidate, [])
        self.assertEqual(h._ip4_multicast, [])
        self.assertEqual(h._ip6_multicast, [])
        self.assertEqual(h._ip4_id, 0)
        self.assertEqual(h._ip4_frag_table.flows, {})
        self.assertEqual(h._ip6_frag_table.flows, {})
        self.assertEqual(h._interface_mtu, 1500)

    def test__stack__packet_handler__init__ip4_host_seeds_candidate(self) -> None:
        """
        Ensure passing 'ip4_host=' seeds the candidate list (the
        address still has to pass DAD before moving to _ip4_ifaddr).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = PacketHandlerL2(
            mac_address=STACK__MAC_UNICAST,
            interface_mtu=1500,
            ip4_support=False,
            ip6_support=False,
            ip4_host=STACK__IP4_HOST,
        )

        self.assertEqual(
            h._ip4_ifaddr_candidate,
            [STACK__IP4_HOST],
            msg="ip4_host constructor arg must seed the _ip4_ifaddr_candidate list.",
        )

    def test__stack__packet_handler__init__ip6_host_seeds_candidate(self) -> None:
        """
        Ensure passing 'ip6_host=' seeds the candidate list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = PacketHandlerL2(
            mac_address=STACK__MAC_UNICAST,
            interface_mtu=1500,
            ip4_support=False,
            ip6_support=False,
            ip6_host=STACK__IP6_HOST,
        )

        self.assertEqual(
            h._ip6_ifaddr_candidate,
            [STACK__IP6_HOST],
            msg="ip6_host constructor arg must seed the _ip6_ifaddr_candidate list.",
        )


class TestPacketHandlerAddressProperties(TestCase):
    """
    The address-list property accessor tests.
    """

    def test__stack__packet_handler__init__ip4_unicast_derived_from_hosts(self) -> None:
        """
        Ensure '_ip4_unicast' returns the addresses of the configured
        IPv4 hosts in order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._ip4_ifaddr = [STACK__IP4_HOST]

        self.assertEqual(h._ip4_unicast, [STACK__IP4_HOST.address])
        self.assertEqual(h.ip4_unicast, [STACK__IP4_HOST.address])

    def test__stack__packet_handler__init__ip6_unicast_derived_from_hosts(self) -> None:
        """
        Ensure '_ip6_unicast' returns the addresses of the configured
        IPv6 hosts in order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._ip6_ifaddr = [STACK__IP6_HOST]

        self.assertEqual(h._ip6_unicast, [STACK__IP6_HOST.address])
        self.assertEqual(h.ip6_unicast, [STACK__IP6_HOST.address])

    def test__stack__packet_handler__init__ip4_broadcast_includes_limited(self) -> None:
        """
        Ensure '_ip4_broadcast' returns per-host network broadcasts
        plus the all-ones limited broadcast.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._ip4_ifaddr = [STACK__IP4_HOST]

        self.assertIn(
            STACK__IP4_HOST.network.broadcast,
            h._ip4_broadcast,
            msg="Per-host network broadcast must appear in _ip4_broadcast.",
        )
        self.assertIn(
            Ip4Address(0xFFFFFFFF),
            h._ip4_broadcast,
            msg="255.255.255.255 (limited broadcast) must always appear in _ip4_broadcast.",
        )


class TestPacketHandlerAddressAssignment(TestCase):
    """
    The assign / remove host+multicast helper tests.
    """

    def test__stack__packet_handler__init__assign_remove_ip4_host(self) -> None:
        """
        Ensure '_assign_ip4_host' / '_remove_ip4_host' mutate the
        host list without affecting anything else.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()

        h._assign_ip4_host(STACK__IP4_HOST)
        self.assertEqual(h._ip4_ifaddr, [STACK__IP4_HOST])
        self.assertEqual(h._ip4_unicast, [STACK__IP4_HOST.address])

        h._remove_ip4_host(STACK__IP4_HOST)
        self.assertEqual(h._ip4_ifaddr, [])
        self.assertEqual(h._ip4_unicast, [])

    def test__stack__packet_handler__init__l2_ip6_assign_also_adds_mac_multicast(self) -> None:
        """
        Ensure PacketHandlerL2's '_assign_ip6_multicast' appends the
        matching multicast MAC to '_mac_multicast' (needed so the L2
        filter accepts frames for the joined group) and invokes the
        MLDv2 state-change sender.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._send_mld_state_change = MagicMock()  # type: ignore[method-assign]

        addr = Ip6Address("ff02::1:3")
        h.assign_ip6_multicast(addr)

        self.assertIn(addr, h._ip6_multicast)
        self.assertIn(addr.multicast_mac, h._mac_multicast)
        h._send_mld_state_change.assert_called_once()

    def test__stack__packet_handler__init__l2_ip6_remove_also_removes_mac_multicast(self) -> None:
        """
        Ensure '_remove_ip6_multicast' removes both the IPv6 entry and
        the matching MAC multicast.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._send_mld_state_change = MagicMock()  # type: ignore[method-assign]

        addr = Ip6Address("ff02::1:3")
        h.assign_ip6_multicast(addr)
        h.remove_ip6_multicast(addr)

        self.assertNotIn(addr, h._ip6_multicast)
        self.assertNotIn(addr.multicast_mac, h._mac_multicast)

    def test__stack__packet_handler__init__l3_ip6_assign_no_mac_side_effects(self) -> None:
        """
        Ensure PacketHandlerL3 '_assign_ip6_multicast' does NOT touch
        any MAC multicast list (L3 stack has no MAC filter).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l3_handler()
        h._send_mld_state_change = MagicMock()  # type: ignore[method-assign]

        addr = Ip6Address("ff02::1:3")
        h.assign_ip6_multicast(addr)

        self.assertIn(addr, h._ip6_multicast)
        self.assertFalse(
            hasattr(h, "_mac_multicast"),
            msg="PacketHandlerL3 must not carry a _mac_multicast attribute.",
        )


class TestPacketHandlerL3CreateStackAddressing(TestCase):
    """
    The L3-specific addressing-bootstrap tests.
    """

    def test__stack__packet_handler__init__l3_create_ip4_addressing_promotes_candidates(self) -> None:
        """
        Ensure PacketHandlerL3's '_create_stack_ip4_addressing' moves
        every candidate into '_ip4_ifaddr' (no DAD on L3).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l3_handler()
        h._ip4_ifaddr_candidate = [STACK__IP4_HOST]

        h._create_stack_ip4_addressing()

        self.assertEqual(h._ip4_ifaddr, [STACK__IP4_HOST])
        self.assertEqual(h._ip4_ifaddr_candidate, [])

    def test__stack__packet_handler__init__l3_create_ip4_disables_ip4_when_empty(self) -> None:
        """
        Ensure '_create_stack_ip4_addressing' turns off '_ip4_support'
        when no candidates could be assigned.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l3_handler()
        h._ip4_support = True
        h._ip4_ifaddr_candidate = []

        h._create_stack_ip4_addressing()

        self.assertFalse(h._ip4_support)

    def test__stack__packet_handler__init__l3_create_ip6_addressing_promotes_and_joins_all_nodes(self) -> None:
        """
        Ensure PacketHandlerL3's '_create_stack_ip6_addressing' joins
        ff02::1 (all-nodes) and promotes every candidate.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l3_handler()
        h._send_mld_state_change = MagicMock()  # type: ignore[method-assign]
        h._ip6_ifaddr_candidate = [STACK__IP6_HOST]

        h._create_stack_ip6_addressing()

        self.assertIn(Ip6Address("ff02::1"), h._ip6_multicast)
        self.assertIn(STACK__IP6_HOST, h._ip6_ifaddr)


class TestPacketHandlerL2SubsystemLoop(TestCase):
    """
    The L2 subsystem-loop dispatch tests.
    """

    def test__stack__packet_handler__init__l2_loop_dispatches_ethernet_2(self) -> None:
        """
        Ensure an Ethernet II frame (ethertype > 802.3 max) is routed
        to '_phrx_ethernet', and an 802.3 frame is routed to
        '_phrx_ethernet_802_3'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._phrx_ethernet = MagicMock()  # type: ignore[method-assign]
        h._phrx_ethernet_802_3 = MagicMock()  # type: ignore[method-assign]

        eth2 = MagicMock()
        eth2.frame = b"\x00" * 12 + b"\x08\x00" + b"\x00" * 46
        eth_802_3 = MagicMock()
        eth_802_3.frame = b"\x00" * 12 + b"\x00\x46" + b"\x00" * 60

        mock_rx_ring = create_autospec(RxRing, spec_set=True)
        mock_rx_ring.dequeue.side_effect = [eth2, eth_802_3, None]
        h._rx_ring = mock_rx_ring
        h._subsystem_loop()
        h._subsystem_loop()
        h._subsystem_loop()

        h._phrx_ethernet.assert_called_once_with(eth2)
        h._phrx_ethernet_802_3.assert_called_once_with(eth_802_3)

    def test__stack__packet_handler__init__l2_loop_uses_injected_rx_ring(self) -> None:
        """
        Ensure the L2 subsystem loop dequeues from the handler's own
        injected 'self._rx_ring' and never reaches through to the
        global 'stack.rx_ring'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()
        h._phrx_ethernet = MagicMock()  # type: ignore[method-assign]
        h._phrx_ethernet_802_3 = MagicMock()  # type: ignore[method-assign]

        eth2 = MagicMock()
        eth2.frame = b"\x00" * 12 + b"\x08\x00" + b"\x00" * 46

        injected = create_autospec(RxRing, spec_set=True)
        injected.dequeue.side_effect = [eth2, None]
        h._rx_ring = injected

        global_ring = create_autospec(RxRing, spec_set=True)
        with patch.object(stack, "rx_ring", global_ring, create=True):
            h._subsystem_loop()
            h._subsystem_loop()

        h._phrx_ethernet.assert_called_once_with(eth2)
        global_ring.dequeue.assert_not_called()


class TestPacketHandlerL3SubsystemLoop(TestCase):
    """
    The L3 subsystem-loop dispatch tests.
    """

    def test__stack__packet_handler__init__l3_loop_routes_by_ethertype(self) -> None:
        """
        Ensure the L3 loop inspects bytes 2-3 of the TUN framing to
        select the EtherType-registry handler, advances the frame
        pointer past the 4-byte TUN header before invoking it, and
        drops an unregistered EtherType without dispatching.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l3_handler_supported()
        # Overwrite the real IP handlers with spies so dispatch is
        # observable; the loop's only dispatch path is the registry.
        ip4_handler = MagicMock()
        ip6_handler = MagicMock()
        h._ethertype_registry.register(EtherType.IP4, ip4_handler)
        h._ethertype_registry.register(EtherType.IP6, ip6_handler)

        # TUN framing: 4-byte header; bytes[2:4] = EtherType.
        ip4_packet = MagicMock()
        ip4_packet.frame = b"\x00\x00\x08\x00" + b"IPV4_PAYLOAD"
        ip6_packet = MagicMock()
        ip6_packet.frame = b"\x00\x00\x86\xdd" + b"IPV6_PAYLOAD"
        unknown = MagicMock()
        unknown.frame = b"\x00\x00\xff\xff" + b"UNKNOWN_PAYLOAD"

        mock_rx_ring = create_autospec(RxRing, spec_set=True)
        mock_rx_ring.dequeue.side_effect = [ip4_packet, ip6_packet, unknown, None]
        h._rx_ring = mock_rx_ring
        h._subsystem_loop()
        h._subsystem_loop()
        h._subsystem_loop()

        ip4_handler.assert_called_once_with(ip4_packet)
        ip6_handler.assert_called_once_with(ip6_packet)
        self.assertEqual(
            ip4_packet.frame,
            b"IPV4_PAYLOAD",
            msg="The 4-byte TUN PI header must be stripped before the handler is invoked.",
        )
        # The unknown ethertype case logs a warning but doesn't dispatch.

    def test__stack__packet_handler__init__l3_loop_gates_on_support_flags(self) -> None:
        """
        Ensure a support-disabled L3 interface registers no IPv4 / IPv6
        EtherType handlers, so the loop's registry lookup misses and the
        frame is dropped with no dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l3_handler()  # ip4_support=False, ip6_support=False

        self.assertIsNone(
            h._ethertype_registry.get(EtherType.IP4),
            msg="An IPv4-disabled L3 interface must not register the IPv4 handler.",
        )
        self.assertIsNone(
            h._ethertype_registry.get(EtherType.IP6),
            msg="An IPv6-disabled L3 interface must not register the IPv6 handler.",
        )

        # Driving the loop with IP4 / IP6 frames must not raise and must
        # not dispatch (the registry is empty).
        ip4_packet = MagicMock()
        ip4_packet.frame = b"\x00\x00\x08\x00" + b"IPV4_PAYLOAD"
        ip6_packet = MagicMock()
        ip6_packet.frame = b"\x00\x00\x86\xdd" + b"IPV6_PAYLOAD"

        mock_rx_ring = create_autospec(RxRing, spec_set=True)
        mock_rx_ring.dequeue.side_effect = [ip4_packet, ip6_packet, None]
        h._rx_ring = mock_rx_ring
        h._subsystem_loop()
        h._subsystem_loop()

        self.assertEqual(
            ip4_packet.frame,
            b"\x00\x00\x08\x00" + b"IPV4_PAYLOAD",
            msg="A dropped frame must not be advanced past the TUN PI header.",
        )


class TestPacketHandlerTxRingInjection(TestCase):
    """
    The packet-handler injected-TX-ring send-out tests.
    """

    def test__stack__packet_handler__init__ethernet_send_uses_injected_tx_ring(self) -> None:
        """
        Ensure an outbound Ethernet frame with a specified destination
        MAC is enqueued onto the handler's own injected 'self._tx_ring'
        and never reaches through to the global 'stack.tx_ring'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        h = _build_l2_handler()

        injected = create_autospec(TxRing, spec_set=True)
        h._tx_ring = injected

        global_ring = create_autospec(TxRing, spec_set=True)
        with patch.object(stack, "tx_ring", global_ring, create=True):
            h._phtx_ethernet(
                ethernet__src=MacAddress("02:00:00:00:00:07"),
                ethernet__dst=MacAddress("02:00:00:00:00:99"),
            )

        injected.enqueue.assert_called_once()
        global_ring.enqueue.assert_not_called()


class TestPacketHandlerIp4IdGenerator(TestCase):
    """
    The per-interface IPv4 Identification generator tests.
    """

    def test__stack__packet_handler__init__ip4_id_first_value_is_one(self) -> None:
        """
        Ensure the first generated IPv4 Identification is 1 (the
        counter starts at 0 and pre-increments), preserving the
        legacy first-fragmented-packet value.

        Reference: RFC 791 §2.3 (Identification field).
        """

        h = _build_l2_handler()

        self.assertEqual(
            h._ip4_tx._next_ip4_id(),
            1,
            msg="The first generated IPv4 Identification must be 1.",
        )

    def test__stack__packet_handler__init__ip4_id_wraps_at_16_bits(self) -> None:
        """
        Ensure the IPv4 Identification generator wraps modulo 2^16
        instead of overflowing past the 16-bit wire field — the
        value after 0xFFFF must be 0, then 1.

        Reference: RFC 791 §2.3 (Identification is a 16-bit field).
        """

        h = _build_l2_handler()
        h._ip4_id = 0xFFFF

        self.assertEqual(
            h._ip4_tx._next_ip4_id(),
            0,
            msg="The IPv4 Identification must wrap from 0xFFFF to 0, not overflow to 0x10000.",
        )
        self.assertEqual(
            h._ip4_tx._next_ip4_id(),
            1,
            msg="The IPv4 Identification must continue from 0 to 1 after wrapping.",
        )

    def test__stack__packet_handler__init__ip4_id_concurrent_values_are_unique(self) -> None:
        """
        Ensure concurrent IPv4 Identification generation hands every
        caller a distinct value — the masked counter increment is
        atomic, so no two of N concurrent fragmented sends collide
        (which would corrupt reassembly at the peer).

        Reference: RFC 791 §2.3 (Identification distinguishes
        fragments of distinct datagrams).
        """

        h = _build_l2_handler()
        count = 500
        results: list[int] = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(parties=count)

        def _worker() -> None:
            barrier.wait()
            value = h._ip4_tx._next_ip4_id()
            with results_lock:
                results.append(value)

        threads = [threading.Thread(target=_worker) for _ in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(
            len(set(results)),
            count,
            msg="Concurrent IPv4 Identification generation must hand every caller a distinct value.",
        )


def _build_l2_handler_supported() -> PacketHandlerL2:
    """
    Build a 'PacketHandlerL2' with IPv4/IPv6 protocol support enabled
    but DHCP / SLAAC autoconfig disabled and no static host, so the
    constructor populates the dispatch registries without spawning any
    addressing-acquisition threads.
    """

    return PacketHandlerL2(
        mac_address=STACK__MAC_UNICAST,
        interface_mtu=1500,
        ip4_support=True,
        ip4_dhcp=False,
        ip6_support=True,
        ip6_lla_autoconfig=False,
        ip6_gua_autoconfig=False,
    )


def _build_l3_handler_supported() -> PacketHandlerL3:
    """
    Build a 'PacketHandlerL3' with IPv4/IPv6 protocol support enabled
    and no addressing autoconfig.
    """

    return PacketHandlerL3(
        interface_mtu=1500,
        ip4_support=True,
        ip6_support=True,
    )


class TestPacketHandlerInitDispatchRegistry(TestCase):
    """
    The per-interface RX dispatch-registry membership tests.
    """

    def test__stack__packet_handler__init__l2_registers_arp_when_ip4_supported(self) -> None:
        """
        Ensure an IPv4-supporting L2 (TAP) interface registers the ARP
        EtherType in its link-layer dispatch registry — ARP is the
        link-layer half of IPv4 on a broadcast link.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_l2_handler_supported()

        self.assertIsNotNone(
            handler._ethertype_registry.get(EtherType.ARP),
            msg="An IPv4-supporting L2 interface must register the ARP handler.",
        )

    def test__stack__packet_handler__init__l3_never_registers_arp(self) -> None:
        """
        Ensure an L3 (TUN) interface never registers ARP even with IPv4
        support enabled — a point-to-point TUN link has no link-layer
        address resolution.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_l3_handler_supported()

        self.assertIsNone(
            handler._ethertype_registry.get(EtherType.ARP),
            msg="An L3 (TUN) interface must not register the ARP handler.",
        )

    def test__stack__packet_handler__init__ethertype_registry_gates_on_support(self) -> None:
        """
        Ensure link-layer dispatch-registry membership tracks the
        protocol-support flags: a support-disabled interface registers
        neither ARP nor the IPv4 / IPv6 EtherTypes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_l2_handler()  # ip4_support=False, ip6_support=False

        self.assertIsNone(
            handler._ethertype_registry.get(EtherType.ARP),
            msg="A support-disabled interface must not register ARP.",
        )
        self.assertIsNone(
            handler._ethertype_registry.get(EtherType.IP4),
            msg="An IPv4-disabled interface must not register the IPv4 EtherType.",
        )
        self.assertIsNone(
            handler._ethertype_registry.get(EtherType.IP6),
            msg="An IPv6-disabled interface must not register the IPv6 EtherType.",
        )
