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
This module contains tests for the Phase-1 link-control API
('LinkApi') in 'pytcp/lib/link_api.py'. Phase 0 covers the
read-only minimum surface — 'mac_address', 'mtu', and
'interface_layer' — that closes the
'packet_handler._mac_unicast' reach-through used by the
DHCPv4 and RFC 3927 link-local construction call sites.

pytcp/tests/unit/stack/test__stack__link.py

ver 3.0.8
"""

import inspect
from typing import TYPE_CHECKING, cast
from unittest import TestCase
from unittest.mock import patch

from net_addr import MacAddress
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx, PacketStatsTx
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.stack.link import LinkApi, LinkFlag, LinkStats

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


class _FakeRing:
    """
    Minimal ring stand-in exposing the 'set_mtu' mutator that the packet
    handler's 'set_interface_mtu' calls to resize the ring.
    """

    def __init__(self, *, mtu: int) -> None:
        self._mtu = mtu

    def set_mtu(self, mtu: int, /) -> None:
        self._mtu = mtu


class _FakePacketHandlerL2:
    """
    Minimal L2 packet-handler stand-in for 'LinkApi' tests —
    exposes only the attributes 'LinkApi' reads
    ('_mac_unicast', '_interface_mtu', '_interface_layer',
    '_interface_name'). Using a hand-rolled class avoids
    the autospec ceremony for the production
    PacketHandlerL2 class (which carries ~50 attributes
    irrelevant to the API surface under test).
    """

    _interface_layer: InterfaceLayer = InterfaceLayer.L2

    def __init__(
        self,
        *,
        mac_unicast: MacAddress,
        interface_mtu: int,
        interface_name: str | None = None,
        packet_stats_rx: PacketStatsRx | None = None,
        packet_stats_tx: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        self._mac_unicast = mac_unicast
        self._interface_mtu = interface_mtu
        self._interface_name = interface_name
        self._packet_stats_rx = packet_stats_rx if packet_stats_rx is not None else PacketStatsRx()
        self._packet_stats_tx = packet_stats_tx if packet_stats_tx is not None else PacketStatsTx()
        self._link_stats = link_stats if link_stats is not None else LinkStatsCounters()
        # Ring stand-ins so 'set_mtu' (which resizes the bound
        # handler's own rings) has something to write; tests that
        # assert per-interface ring resize replace these.
        self._tx_ring: _FakeRing = _FakeRing(mtu=interface_mtu)
        self._rx_ring: _FakeRing = _FakeRing(mtu=interface_mtu)

    @property
    def interface_layer(self) -> InterfaceLayer:
        return self._interface_layer

    @property
    def interface_mtu(self) -> int:
        return self._interface_mtu

    @property
    def interface_name(self) -> str | None:
        return self._interface_name

    @property
    def mac_unicast(self) -> MacAddress | None:
        return self._mac_unicast

    @property
    def packet_stats_rx(self) -> PacketStatsRx:
        return self._packet_stats_rx

    @property
    def packet_stats_tx(self) -> PacketStatsTx:
        return self._packet_stats_tx

    @property
    def link_stats(self) -> LinkStatsCounters:
        return self._link_stats

    def set_interface_mtu(self, mtu: int, /) -> None:
        self._interface_mtu = mtu
        self._tx_ring.set_mtu(mtu)
        self._rx_ring.set_mtu(mtu)

    def set_mac_address(self, mac_address: MacAddress, /) -> None:
        self._mac_unicast = mac_address

    def set_ifindex(self, ifindex: int, /) -> None:
        self._ifindex = ifindex


class _FakePacketHandlerL3:
    """
    Minimal L3 packet-handler stand-in for 'LinkApi' tests.
    Has '_interface_mtu' and '_interface_layer' but
    deliberately NO '_mac_unicast' attribute — L3 (TUN) has
    no Ethernet layer and therefore no MAC.
    """

    _interface_layer: InterfaceLayer = InterfaceLayer.L3

    def __init__(
        self,
        *,
        interface_mtu: int,
        interface_name: str | None = None,
        packet_stats_rx: PacketStatsRx | None = None,
        packet_stats_tx: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        self._interface_mtu = interface_mtu
        self._interface_name = interface_name
        self._packet_stats_rx = packet_stats_rx if packet_stats_rx is not None else PacketStatsRx()
        self._packet_stats_tx = packet_stats_tx if packet_stats_tx is not None else PacketStatsTx()
        self._link_stats = link_stats if link_stats is not None else LinkStatsCounters()

    @property
    def interface_layer(self) -> InterfaceLayer:
        return self._interface_layer

    @property
    def interface_mtu(self) -> int:
        return self._interface_mtu

    @property
    def interface_name(self) -> str | None:
        return self._interface_name

    @property
    def mac_unicast(self) -> MacAddress | None:
        # L3 (TUN) has no Ethernet layer and therefore no MAC,
        # mirroring 'PacketHandler.mac_unicast' returning None.
        return None

    @property
    def packet_stats_rx(self) -> PacketStatsRx:
        return self._packet_stats_rx

    @property
    def packet_stats_tx(self) -> PacketStatsTx:
        return self._packet_stats_tx

    @property
    def link_stats(self) -> LinkStatsCounters:
        return self._link_stats

    def set_interface_mtu(self, mtu: int, /) -> None:
        # L3 (TUN) has no rings to resize in this stand-in.
        self._interface_mtu = mtu


class TestLinkApiMacAddress(TestCase):
    """
    'LinkApi.mac_address' returns the bound packet handler's
    MAC on L2, and None on L3 (where there is no MAC).
    """

    def test__link_api__mac_address__l2_returns_packet_handler_mac(self) -> None:
        """
        Ensure 'mac_address' returns the unicast MAC of the
        bound L2 packet handler.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.mac_address,
            MacAddress("02:00:00:00:00:07"),
            msg="LinkApi.mac_address must reflect the bound L2 handler's _mac_unicast.",
        )

    def test__link_api__mac_address__l3_returns_none(self) -> None:
        """
        Ensure 'mac_address' returns None when bound to an L3
        packet handler — L3 (TUN) has no Ethernet layer and
        therefore no MAC to report.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertIsNone(
            api.mac_address,
            msg="LinkApi.mac_address must be None on L3 (no Ethernet, no MAC).",
        )


class TestLinkApiMtu(TestCase):
    """
    'LinkApi.mtu' returns the bound packet handler's
    interface MTU as an integer.
    """

    def test__link_api__mtu__l2_returns_packet_handler_mtu(self) -> None:
        """
        Ensure 'mtu' returns the bound L2 packet handler's
        '_interface_mtu' as a plain int.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.mtu,
            1500,
            msg="LinkApi.mtu must reflect the bound handler's _interface_mtu.",
        )

    def test__link_api__mtu__non_default_value(self) -> None:
        """
        Ensure 'mtu' returns whatever non-default value the
        bound packet handler advertises — the API must not
        cache or alias the value at construction time.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=9000,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.mtu,
            9000,
            msg="LinkApi.mtu must read the live handler attribute, not a cached value.",
        )

    def test__link_api__mtu__l3_returns_packet_handler_mtu(self) -> None:
        """
        Ensure 'mtu' returns the bound L3 packet handler's
        '_interface_mtu' even when no MAC is set.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertEqual(
            api.mtu,
            1500,
            msg="LinkApi.mtu must work on L3 handlers (no MAC) as well.",
        )


class TestLinkApiName(TestCase):
    """
    'LinkApi.name' returns the interface name recorded on
    the bound packet handler, or None if no name was
    plumbed through 'stack.init()'.
    """

    def test__link_api__name__returns_packet_handler_name(self) -> None:
        """
        Ensure 'name' returns the string recorded on the
        bound packet handler's '_interface_name' attribute
        (e.g. 'tap7').

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            interface_name="tap7",
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.name,
            "tap7",
            msg="LinkApi.name must reflect the bound handler's _interface_name.",
        )

    def test__link_api__name__returns_none_when_not_set(self) -> None:
        """
        Ensure 'name' returns None when the bound packet
        handler was constructed without an
        '_interface_name' value — e.g. by a unit-test
        fixture or 'mock__init' that did not thread the
        name through.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertIsNone(
            api.name,
            msg="LinkApi.name must be None when no interface name was recorded.",
        )

    def test__link_api__name__l3_handler(self) -> None:
        """
        Ensure 'name' works on L3 (TUN) handlers — the
        interface name is recorded on the base packet
        handler, independent of L2/L3 layer.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(
            interface_mtu=1500,
            interface_name="tun7",
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertEqual(
            api.name,
            "tun7",
            msg="LinkApi.name must work on L3 (TUN) handlers.",
        )


class TestLinkApiIsRunning(TestCase):
    """
    'LinkApi.is_running' reflects whether the stack has been
    started (via 'stack.start()') and not yet stopped (via
    'stack.stop()'). Mirrors Linux's
    'IFF_UP + IFF_RUNNING' state.
    """

    def test__link_api__is_running__false_before_start(self) -> None:
        """
        Ensure 'is_running' is False when the stack has been
        initialized but 'stack.start()' has not yet been
        called (i.e. 'stack.stack_running' is its default
        False).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", False))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertFalse(
            api.is_running,
            msg="LinkApi.is_running must be False before stack.start().",
        )

    def test__link_api__is_running__true_after_start(self) -> None:
        """
        Ensure 'is_running' is True when 'stack.start()' has
        completed (i.e. 'stack.stack_running' is True).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", True))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertTrue(
            api.is_running,
            msg="LinkApi.is_running must be True after stack.start().",
        )

    def test__link_api__is_running__false_after_stop(self) -> None:
        """
        Ensure 'is_running' is False after 'stack.stop()' has
        cleared 'stack.stack_running'.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        # Simulate the post-stop state: stack_running cleared.
        self.enterContext(patch.object(stack, "stack_running", False))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertFalse(
            api.is_running,
            msg="LinkApi.is_running must be False after stack.stop().",
        )


class TestLinkApiFlags(TestCase):
    """
    'LinkApi.flags' returns a frozenset of 'LinkFlag' enum
    values derived from the bound packet handler's
    interface layer. L2 (TAP) carries BROADCAST +
    MULTICAST; L3 (TUN) carries POINTOPOINT. Mirrors
    Linux's IFF_* flag selection from
    'linux/include/uapi/linux/if_link.h'.
    """

    def test__link_api__flags__l2_broadcast_and_multicast(self) -> None:
        """
        Ensure 'flags' for an L2 (TAP) handler includes
        BROADCAST and MULTICAST — TAP interfaces carry
        Ethernet which supports both.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.flags,
            frozenset({LinkFlag.BROADCAST, LinkFlag.MULTICAST}),
            msg="L2 LinkApi.flags must equal {BROADCAST, MULTICAST}.",
        )

    def test__link_api__flags__l3_pointopoint(self) -> None:
        """
        Ensure 'flags' for an L3 (TUN) handler includes
        POINTOPOINT — TUN carries L3 frames without an
        Ethernet layer, so broadcast / multicast do not
        apply.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertEqual(
            api.flags,
            frozenset({LinkFlag.POINTOPOINT}),
            msg="L3 LinkApi.flags must equal {POINTOPOINT}.",
        )

    def test__link_api__flags__returns_frozenset(self) -> None:
        """
        Ensure 'flags' returns an immutable 'frozenset' so
        the caller cannot mutate the returned value into
        stack-internal state.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertIsInstance(
            api.flags,
            frozenset,
            msg="LinkApi.flags must return a frozenset (copy-by-value).",
        )


class TestLinkApiStats(TestCase):
    """
    'LinkApi.stats' returns a frozen 'LinkStats' snapshot
    aggregating the per-protocol 'PacketStatsRx' /
    'PacketStatsTx' counters and the link-level
    'LinkStatsCounters' into the eight Linux-canonical
    buckets (rx_packets / tx_packets / rx_bytes / tx_bytes
    / rx_errors / tx_errors / rx_dropped / tx_dropped).
    """

    def test__link_api__stats__empty_fixture_returns_all_zeros(self) -> None:
        """
        Ensure 'stats' on a freshly-constructed fixture
        (no traffic seen) returns 'LinkStats' with every
        bucket at zero.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats,
            LinkStats(
                rx_packets=0,
                rx_bytes=0,
                rx_errors=0,
                rx_dropped=0,
                tx_packets=0,
                tx_bytes=0,
                tx_errors=0,
                tx_dropped=0,
            ),
            msg="LinkApi.stats on an empty fixture must be all zeros.",
        )

    def test__link_api__stats__l2_rx_packets_from_ethernet_pre_parse(self) -> None:
        """
        Ensure 'rx_packets' on an L2 (TAP) handler reflects
        the 'ethernet__pre_parse' counter.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        rx = PacketStatsRx()
        rx.ethernet__pre_parse = 5
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            packet_stats_rx=rx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.rx_packets,
            5,
            msg="L2 rx_packets must equal ethernet__pre_parse.",
        )

    def test__link_api__stats__l3_rx_packets_from_ip_pre_parse(self) -> None:
        """
        Ensure 'rx_packets' on an L3 (TUN) handler reflects
        the sum of 'ip4__pre_parse' and 'ip6__pre_parse'
        counters (no Ethernet layer on TUN).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        rx = PacketStatsRx()
        rx.ip4__pre_parse = 3
        rx.ip6__pre_parse = 7
        handler = _FakePacketHandlerL3(
            interface_mtu=1500,
            packet_stats_rx=rx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertEqual(
            api.stats.rx_packets,
            10,
            msg="L3 rx_packets must equal ip4__pre_parse + ip6__pre_parse.",
        )

    def test__link_api__stats__rx_bytes_from_link_stats(self) -> None:
        """
        Ensure 'rx_bytes' reads directly from the
        'LinkStatsCounters.rx_bytes' field bumped by the
        RxRing at frame-receive time.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        link = LinkStatsCounters()
        link.rx_bytes = 12345
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            link_stats=link,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.rx_bytes,
            12345,
            msg="rx_bytes must reflect the link-level LinkStatsCounters.rx_bytes.",
        )

    def test__link_api__stats__tx_bytes_from_link_stats(self) -> None:
        """
        Ensure 'tx_bytes' reads directly from the
        'LinkStatsCounters.tx_bytes' field bumped by the
        TxRing at frame-send time.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        link = LinkStatsCounters()
        link.tx_bytes = 67890
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            link_stats=link,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.tx_bytes,
            67890,
            msg="tx_bytes must reflect the link-level LinkStatsCounters.tx_bytes.",
        )

    def test__link_api__stats__rx_errors_sums_failed_parse_drops(self) -> None:
        """
        Ensure 'rx_errors' sums every '*__failed_parse__drop'
        counter across PacketStatsRx — these are structural
        validation failures (couldn't decode the wire
        format).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        rx = PacketStatsRx()
        rx.ethernet__failed_parse__drop = 1
        rx.ip4__failed_parse__drop = 2
        rx.tcp__failed_parse__drop = 3
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            packet_stats_rx=rx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.rx_errors,
            6,
            msg="rx_errors must sum every *__failed_parse__drop counter.",
        )

    def test__link_api__stats__rx_dropped_sums_other_drops(self) -> None:
        """
        Ensure 'rx_dropped' sums every '__drop' counter that
        is NOT a '__failed_parse__drop' — these are policy /
        config drops, not structural failures.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        rx = PacketStatsRx()
        rx.ethernet__dst_unknown__drop = 2
        rx.ip4__no_proto_support__drop = 3
        rx.udp__no_socket_match__icmp4_unreachable_suppressed = 0  # not a __drop
        rx.ethernet__failed_parse__drop = 7  # error, NOT counted in dropped
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            packet_stats_rx=rx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.rx_dropped,
            5,
            msg="rx_dropped must sum non-failed_parse __drop counters.",
        )

    def test__link_api__stats__tx_errors_sums_tx_ring_drops(self) -> None:
        """
        Ensure 'tx_errors' sums every 'tx_ring__*__drop'
        counter — kernel-level transmit failures (queue
        full, OSError on writev).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        tx = PacketStatsTx()
        tx.tx_ring__queue_full__drop = 2
        tx.tx_ring__os_error__drop = 3
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            packet_stats_tx=tx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.tx_errors,
            5,
            msg="tx_errors must sum every tx_ring__*__drop counter.",
        )

    def test__link_api__stats__tx_dropped_sums_other_drops(self) -> None:
        """
        Ensure 'tx_dropped' sums every '__drop' counter on
        PacketStatsTx that is NOT a 'tx_ring__*' counter —
        these are policy / config TX drops (broadcast
        disallowed, scope mismatch, src not owned, etc.).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        tx = PacketStatsTx()
        tx.ip4__dst_broadcast_disallowed__drop = 1
        tx.ip4__link_local_scope_mismatch__drop = 2
        tx.ip6__src_scope_mismatch__drop = 4
        tx.tx_ring__queue_full__drop = 99  # error, NOT counted in dropped
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            packet_stats_tx=tx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.stats.tx_dropped,
            7,
            msg="tx_dropped must sum non-tx_ring __drop counters.",
        )

    def test__link_api__stats__returns_frozen_dataclass(self) -> None:
        """
        Ensure 'stats' returns a frozen dataclass (mutation
        raises) so the caller cannot mutate stack-internal
        state through the returned snapshot.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        from dataclasses import FrozenInstanceError

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        snapshot = api.stats
        with self.assertRaises(FrozenInstanceError):
            snapshot.rx_packets = 999  # type: ignore[misc]


class TestLinkApiSetMtu(TestCase):
    """
    'LinkApi.set_mtu' validates and propagates an MTU
    change to 'packet_handler._interface_mtu' (the canonical
    per-interface source of truth read per-destination via
    'stack.egress_interface_mtu'). Linux 'ip link set eth0
    mtu N' equivalent.
    """

    def test__link_api__set_mtu__updates_packet_handler(self) -> None:
        """
        Ensure 'set_mtu' updates the bound packet handler's
        '_interface_mtu' attribute.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        api.set_mtu(mtu=1400)

        self.assertEqual(
            handler._interface_mtu,
            1400,
            msg="set_mtu must update packet_handler._interface_mtu.",
        )

    def test__link_api__set_mtu__at_minimum_accepted(self) -> None:
        """
        Ensure 'set_mtu' accepts the canonical minimum
        IPv4 link MTU of 68 octets (the lowest legal MTU
        per the IPv4 specification).

        Reference: RFC 791 §3.2 (minimum IPv4 link MTU floor).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        api.set_mtu(mtu=68)

        self.assertEqual(
            handler._interface_mtu,
            68,
            msg="set_mtu must accept the RFC 791 §3.2 floor of 68.",
        )

    def test__link_api__set_mtu__below_minimum_rejected(self) -> None:
        """
        Ensure 'set_mtu' rejects values below the canonical
        minimum IPv4 link MTU of 68 octets.

        Reference: RFC 791 §3.2 (minimum IPv4 link MTU floor).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        with self.assertRaises(ValueError) as ctx:
            api.set_mtu(mtu=67)

        self.assertIn(
            "68",
            str(ctx.exception),
            msg="set_mtu rejection message must cite the minimum.",
        )

    def test__link_api__set_mtu__at_maximum_accepted(self) -> None:
        """
        Ensure 'set_mtu' accepts the uint16 wire-limit
        maximum of 65535.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        api.set_mtu(mtu=65535)

        self.assertEqual(
            handler._interface_mtu,
            65535,
            msg="set_mtu must accept the uint16 ceiling of 65535.",
        )

    def test__link_api__set_mtu__above_maximum_rejected(self) -> None:
        """
        Ensure 'set_mtu' rejects values above the uint16
        wire limit of 65535.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        with self.assertRaises(ValueError) as ctx:
            api.set_mtu(mtu=65536)

        self.assertIn(
            "65535",
            str(ctx.exception),
            msg="set_mtu rejection message must cite the maximum.",
        )


class TestLinkApiSetMacAddress(TestCase):
    """
    'LinkApi.set_mac_address' validates and propagates a
    MAC change to 'packet_handler._mac_unicast'. Linux
    'ip link set eth0 address aa:bb:cc:dd:ee:ff'
    equivalent. Requires the stack to be stopped per the
    Linux 'ip link set down' precondition.
    """

    def test__link_api__set_mac_address__updates_packet_handler(self) -> None:
        """
        Ensure 'set_mac_address' updates the bound packet
        handler's '_mac_unicast' attribute when the stack
        is stopped.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", False))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        api.set_mac_address(mac_address=MacAddress("02:aa:bb:cc:dd:ee"))

        self.assertEqual(
            handler._mac_unicast,
            MacAddress("02:aa:bb:cc:dd:ee"),
            msg="set_mac_address must update packet_handler._mac_unicast when stopped.",
        )

    def test__link_api__set_mac_address__rejected_when_running(self) -> None:
        """
        Ensure 'set_mac_address' rejects the call when the
        stack is running — Linux's 'ip link set down'
        precondition. The operator must call
        'stack.stop()' first.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", True))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        with self.assertRaises(RuntimeError) as ctx:
            api.set_mac_address(mac_address=MacAddress("02:aa:bb:cc:dd:ee"))

        self.assertIn(
            "stop",
            str(ctx.exception).lower(),
            msg="set_mac_address rejection must reference the stop-first precondition.",
        )

    def test__link_api__set_mac_address__multicast_bit_rejected(self) -> None:
        """
        Ensure 'set_mac_address' rejects MACs with the
        IEEE 802 multicast bit set (LSB of the first
        byte) — a multicast MAC is not a valid unicast
        identifier.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", False))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        with self.assertRaises(ValueError) as ctx:
            api.set_mac_address(mac_address=MacAddress("01:00:5e:00:00:01"))

        self.assertIn(
            "unicast",
            str(ctx.exception).lower(),
            msg="set_mac_address multicast rejection must reference the unicast requirement.",
        )

    def test__link_api__set_mac_address__zero_rejected(self) -> None:
        """
        Ensure 'set_mac_address' rejects the all-zero MAC
        ('00:00:00:00:00:00') — the unspecified MAC is not
        a valid unicast identifier.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", False))
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        with self.assertRaises(ValueError) as ctx:
            api.set_mac_address(mac_address=MacAddress("00:00:00:00:00:00"))

        self.assertIn(
            "unicast",
            str(ctx.exception).lower(),
            msg="set_mac_address zero-MAC rejection must reference the unicast requirement.",
        )

    def test__link_api__set_mac_address__l3_rejected(self) -> None:
        """
        Ensure 'set_mac_address' rejects the call on an L3
        (TUN) interface — TUN has no Ethernet layer and
        therefore no MAC to set.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self.enterContext(patch.object(stack, "stack_running", False))
        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        with self.assertRaises(RuntimeError) as ctx:
            api.set_mac_address(mac_address=MacAddress("02:aa:bb:cc:dd:ee"))

        self.assertIn(
            "L3",
            str(ctx.exception),
            msg="set_mac_address L3 rejection must reference the layer.",
        )


class TestLinkApiInterfaceLayer(TestCase):
    """
    'LinkApi.interface_layer' reports the bound packet
    handler's layer (L2 or L3) via the canonical
    'InterfaceLayer' enum.
    """

    def test__link_api__interface_layer__l2(self) -> None:
        """
        Ensure 'interface_layer' returns 'InterfaceLayer.L2'
        when bound to an L2 (TAP) packet handler.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertIs(
            api.interface_layer,
            InterfaceLayer.L2,
            msg="LinkApi.interface_layer must report L2 for TAP handlers.",
        )

    def test__link_api__interface_layer__l3(self) -> None:
        """
        Ensure 'interface_layer' returns 'InterfaceLayer.L3'
        when bound to an L3 (TUN) packet handler.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertIs(
            api.interface_layer,
            InterfaceLayer.L3,
            msg="LinkApi.interface_layer must report L3 for TUN handlers.",
        )


class TestLinkApiInterfaceSelector(TestCase):
    """
    The 'LinkApi.interface(ifindex)' device-selector tests.
    """

    def _install_two_interfaces(self) -> tuple[_FakePacketHandlerL2, _FakePacketHandlerL2]:
        """
        Register two L2 fake interfaces (ifindex 1 @ MTU 1500, ifindex
        2 @ MTU 9000) in a fresh 'stack.interfaces' table for the test.
        """

        iface_1 = _FakePacketHandlerL2(mac_unicast=MacAddress("02:00:00:00:00:01"), interface_mtu=1500)
        iface_2 = _FakePacketHandlerL2(mac_unicast=MacAddress("02:00:00:00:00:02"), interface_mtu=9000)
        table = InterfaceTable()
        table[1] = cast("PacketHandlerL2", iface_1)
        table[2] = cast("PacketHandlerL2", iface_2)
        self.enterContext(patch.object(stack, "interfaces", table))
        return iface_1, iface_2

    def test__link_api__interface__reads_named_interface(self) -> None:
        """
        Ensure 'interface(ifindex)' returns a LinkApi bound to that
        interface so its read properties reflect the named device, not
        the interface the singleton was bound to.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        iface_1, _ = self._install_two_interfaces()
        api = LinkApi(packet_handler=cast("PacketHandlerL2", iface_1))

        self.assertEqual(api.mtu, 1500, msg="The singleton binding reads interface 1.")
        self.assertEqual(api.interface(2).mtu, 9000, msg="interface(2) must read interface 2's MTU.")
        self.assertEqual(
            api.interface(2).mac_address,
            MacAddress("02:00:00:00:00:02"),
            msg="interface(2) must read interface 2's MAC.",
        )

    def test__link_api__interface__unknown_ifindex_raises(self) -> None:
        """
        Ensure 'interface(ifindex)' on an unregistered ifindex raises
        KeyError — the registry has no such device.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        iface_1, _ = self._install_two_interfaces()
        api = LinkApi(packet_handler=cast("PacketHandlerL2", iface_1))

        with self.assertRaises(KeyError):
            api.interface(99)

    def test__link_api__list_interfaces__returns_registered_ifindexes(self) -> None:
        """
        Ensure 'list_interfaces' returns the registered ifindexes in
        ascending order — the dump-all (no-selector) form, Linux
        'ip link show' with no device equivalent.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        iface_1, _ = self._install_two_interfaces()
        api = LinkApi(packet_handler=cast("PacketHandlerL2", iface_1))

        self.assertEqual(api.list_interfaces(), (1, 2), msg="list_interfaces must return the registered ifindexes.")

    def test__link_api__interface__set_mtu_resizes_only_named_interface(self) -> None:
        """
        Ensure 'interface(ifindex).set_mtu' updates that interface's
        own '_interface_mtu' and its own TX/RX rings, leaving other
        interfaces' MTU and rings untouched.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        iface_1, iface_2 = self._install_two_interfaces()
        for iface in (iface_1, iface_2):
            iface._tx_ring = _FakeRing(mtu=iface._interface_mtu)
            iface._rx_ring = _FakeRing(mtu=iface._interface_mtu)

        api = LinkApi(packet_handler=cast("PacketHandlerL2", iface_1))
        api.interface(2).set_mtu(mtu=1400)

        self.assertEqual(iface_2._interface_mtu, 1400, msg="interface(2).set_mtu must update interface 2's MTU.")
        self.assertEqual(iface_2._tx_ring._mtu, 1400, msg="interface(2).set_mtu must resize interface 2's TX ring.")
        self.assertEqual(iface_2._rx_ring._mtu, 1400, msg="interface(2).set_mtu must resize interface 2's RX ring.")
        self.assertEqual(iface_1._interface_mtu, 1500, msg="interface 1's MTU must be untouched.")
        self.assertEqual(iface_1._tx_ring._mtu, 1500, msg="interface 1's TX ring must be untouched.")


class TestLinkApiUnboundTool(TestCase):
    """
    The 'LinkApi' unbound userspace-tool tests — a 'LinkApi()' built
    with no handler is the device-independent tool ('ip link'); it has
    no default device, so every per-interface read MUST select one via
    '.interface(ifindex)' (Linux 'ip link ... dev <ifX>'), and a bare
    per-interface read raises regardless of how many interfaces are
    registered.
    """

    def _install(self, count: int) -> list[_FakePacketHandlerL2]:
        """
        Register 'count' L2 fake interfaces in a fresh 'stack.interfaces'
        table and return them.
        """

        ifaces = [
            _FakePacketHandlerL2(mac_unicast=MacAddress(f"02:00:00:00:00:0{i + 1}"), interface_mtu=1500 + i * 100)
            for i in range(count)
        ]
        table = InterfaceTable()
        for iface in ifaces:
            table.add(cast("PacketHandlerL2", iface))
        self.enterContext(patch.object(stack, "interfaces", table))
        return ifaces

    def test__link_api__unbound_tool__bare_read_raises_with_sole_interface(self) -> None:
        """
        Ensure a bare per-interface read on the unbound tool raises even
        when exactly one interface is registered — there is no
        sole-interface default; the caller must select a device, like
        Linux 'ip link ... dev <ifX>'.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self._install(1)
        tool = LinkApi()

        with self.assertRaises(RuntimeError):
            _ = tool.mtu

    def test__link_api__unbound_tool__bare_read_raises_when_no_interface(self) -> None:
        """
        Ensure a bare read on the unbound tool raises when no interface
        is registered — there is no device to report on.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self._install(0)
        tool = LinkApi()

        with self.assertRaises(RuntimeError):
            _ = tool.mtu

    def test__link_api__unbound_tool__bare_read_raises_when_ambiguous(self) -> None:
        """
        Ensure a bare read on the unbound tool raises when more than one
        interface is registered — the caller must select a device via
        'interface(ifindex)'.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        self._install(2)
        tool = LinkApi()

        with self.assertRaises(RuntimeError):
            _ = tool.mtu

    def test__link_api__unbound_tool__interface_selector_works_when_ambiguous(self) -> None:
        """
        Ensure explicit 'interface(ifindex)' selection on the unbound
        tool reads the named device even when several interfaces are
        registered (where a bare read would be ambiguous).

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        ifaces = self._install(3)
        tool = LinkApi()

        self.assertEqual(
            tool.interface(2).mtu,
            ifaces[1]._interface_mtu,
            msg="interface(2) on the unbound tool must read interface 2's MTU.",
        )


class TestLinkApi__KeywordOnlySignatures(TestCase):
    """
    Pin the keyword-only parameters on the LinkApi mutator methods so
    the '*'→'/' separator mutation is caught.
    """

    def test__link__api_methods_are_keyword_only(self) -> None:
        """
        Ensure the LinkApi mutators keep their parameters keyword-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = {
            "set_mac_address": {"mac_address"},
            "set_mtu": {"mtu"},
        }
        for method, names in expected.items():
            params = inspect.signature(getattr(LinkApi, method)).parameters
            kw_only = {name for name, param in params.items() if param.kind is inspect.Parameter.KEYWORD_ONLY}
            self.assertEqual(
                kw_only,
                names,
                msg=f"LinkApi.{method} must keep keyword-only parameters {names}.",
            )


class TestLinkApiStats__SumGoldens(TestCase):
    """
    Additive-aggregation goldens for the packet-count sums. The
    existing per-counter tests leave the second addend at 0, where
    '+' is indistinguishable from '|' / '^'; these set BOTH addends to
    bit-overlapping values (3 + 5 = 8, while 3 | 5 = 7 and 3 ^ 5 = 6)
    so an operator edit on the sum is caught.
    """

    def test__link_api__stats__l2_packet_sums_are_additive(self) -> None:
        """
        Ensure the L2 rx_packets / tx_packets aggregate the Ethernet and
        802.3 counters by addition (3 + 5 = 8), not bit-OR / XOR.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        rx = PacketStatsRx()
        rx.ethernet__pre_parse = 3
        rx.ethernet_802_3__pre_parse = 5
        tx = PacketStatsTx()
        tx.ethernet__pre_assemble = 3
        tx.ethernet_802_3__pre_assemble = 5
        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
            packet_stats_rx=rx,
            packet_stats_tx=tx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        stats = api.stats
        self.assertEqual(
            (stats.rx_packets, stats.tx_packets),
            (8, 8),
            msg="L2 rx/tx packet sums must be additive: 3 + 5 = 8.",
        )

    def test__link_api__stats__l3_packet_sums_are_additive(self) -> None:
        """
        Ensure the L3 rx_packets / tx_packets aggregate the IPv4 and
        IPv6 counters by addition (3 + 5 = 8), not bit-OR / XOR.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        rx = PacketStatsRx()
        rx.ip4__pre_parse = 3
        rx.ip6__pre_parse = 5
        tx = PacketStatsTx()
        tx.ip4__pre_assemble = 3
        tx.ip6__pre_assemble = 5
        handler = _FakePacketHandlerL3(
            interface_mtu=1500,
            packet_stats_rx=rx,
            packet_stats_tx=tx,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        stats = api.stats
        self.assertEqual(
            (stats.rx_packets, stats.tx_packets),
            (8, 8),
            msg="L3 rx/tx packet sums must be additive: 3 + 5 = 8.",
        )
