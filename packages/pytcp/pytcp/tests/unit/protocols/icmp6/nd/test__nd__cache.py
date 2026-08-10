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
This module contains adapter-level tests for the IPv6 ND
cache. The full FSM behaviour (state transitions, retransmit
cadence, sysctl-driven timers, PERMANENT entries) is exercised
against the generic 'NeighborCache[A]' base in
'pytcp/tests/unit/lib/test__lib__neighbor.py'. This file
covers only what 'NdCache' uniquely contributes: the IPv6-
specific solicit callback and the kw-only public surface
('ip6_address=', 'mac_address=') that legacy call sites
depend on.

pytcp/tests/unit/protocols/icmp6/nd/test__nd__cache.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

from net_addr import Ip6Address, MacAddress
from net_proto import EthernetAssembler
from pytcp.lib.neighbor import NudState
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.packet_handler import PacketHandlerL2
from pytcp.runtime.tx_ring import TxRing
from pytcp.stack import sysctl as sysctl_module


class _NdCacheFixture(TestCase):
    """
    Build a fresh NdCache, silence subsystem logs, restore
    sysctl defaults on tearDown.
    """

    @override
    def setUp(self) -> None:
        """
        Construct cache + log patches.
        """

        self._log_patch = patch("pytcp.lib.neighbor.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self._cache = NdCache()

    @override
    def tearDown(self) -> None:
        """
        Stop log patches and reset sysctl state.
        """

        sysctl_module.reset_to_defaults()
        self._log_patch.stop()
        self._subsystem_log_patch.stop()


class TestNdCacheKwargAPI(_NdCacheFixture):
    """
    The kw-only 'NdCache' public-surface tests.
    """

    def test__nd_cache__add_entry_kw_only_creates_reachable(self) -> None:
        """
        Ensure 'add_entry(ip6_address=..., mac_address=...)'
        kw-only signature creates a NUD_REACHABLE entry and
        stores the supplied MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip6Address("2001:db8::1")
        mac = MacAddress("02:00:00:00:00:01")
        self._cache.add_entry(ip6_address=ip, mac_address=mac)

        entry = self._cache._entries[ip]
        self.assertIs(
            entry.state,
            NudState.REACHABLE,
            msg="add_entry must create a REACHABLE entry.",
        )
        self.assertEqual(
            entry.mac_address,
            mac,
            msg="add_entry must store the supplied MAC.",
        )

    def test__nd_cache__find_entry_kw_only_returns_mac(self) -> None:
        """
        Ensure 'find_entry(ip6_address=...)' kw-only signature
        returns the cached MAC for a REACHABLE entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip6Address("2001:db8::1")
        mac = MacAddress("02:00:00:00:00:01")
        self._cache.add_entry(ip6_address=ip, mac_address=mac)

        result = self._cache.find_entry(ip6_address=ip)
        self.assertEqual(
            result,
            mac,
            msg="find_entry on a REACHABLE entry must return the cached MAC.",
        )

    def test__nd_cache__add_permanent_entry_kw_only(self) -> None:
        """
        Ensure 'add_permanent_entry(ip6_address=...,
        mac_address=...)' installs a NUD_PERMANENT entry
        which dynamic learning cannot displace.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip6Address("2001:db8::1")
        mac = MacAddress("02:00:00:00:00:01")
        other_mac = MacAddress("02:00:00:00:00:02")
        self._cache.add_permanent_entry(ip6_address=ip, mac_address=mac)
        self._cache.add_entry(ip6_address=ip, mac_address=other_mac)

        entry = self._cache._entries[ip]
        self.assertIs(
            entry.state,
            NudState.PERMANENT,
            msg="add_permanent_entry must install a PERMANENT entry.",
        )
        self.assertEqual(
            entry.mac_address,
            mac,
            msg="Dynamic add_entry must NOT displace a PERMANENT entry's MAC.",
        )

    def test__nd_cache__confirm_reachability_kw_only(self) -> None:
        """
        Ensure 'confirm_reachability(ip6_address=...)' kw-only
        signature drives the upper-layer fastpath promotion on
        the named entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip6Address("2001:db8::1")
        mac = MacAddress("02:00:00:00:00:01")
        # Drive entry to STALE with controlled clock.
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache.add_entry(ip6_address=ip, mac_address=mac)
        with sysctl_module.override("neighbor.default.reachable_time", 1):
            with patch("pytcp.lib.neighbor.time.monotonic", return_value=1100.0):
                with patch.object(
                    self._cache._event__stop_subsystem,
                    "wait",
                    return_value=False,
                ):
                    self._cache._subsystem_loop()
        self.assertIs(
            self._cache._entries[ip].state,
            NudState.STALE,
            msg="Pre-condition: entry must be STALE before confirm.",
        )

        self._cache.confirm_reachability(ip6_address=ip)
        self.assertIs(
            self._cache._entries[ip].state,
            NudState.REACHABLE,
            msg="confirm_reachability must promote STALE → REACHABLE.",
        )


class TestNdCacheSolicitCallback(_NdCacheFixture):
    """
    The wire-level solicit-callback dispatch tests.
    """

    def test__nd_cache__solicit_incomplete_fires_multicast_ns(self) -> None:
        """
        Ensure '_solicit_ns(addr, cached_mac=None)' (the
        INCOMPLETE-state solicit) calls
        'stack.packet_handler.send_icmp6_neighbor_solicitation
        (icmp6_ns_target_address=addr)' — the multicast NS
        wire form that targets the solicited-node multicast
        group for first-resolution attempts.

        Reference: RFC 4861 §7.2.2 (multicast NS for INCOMPLETE).
        """

        handler = MagicMock(spec=PacketHandlerL2)
        ip = Ip6Address("2001:db8::1")

        self._cache._owner = handler
        self._cache._solicit_ns(ip, None)

        handler.send_icmp6_neighbor_solicitation.assert_called_once_with(
            icmp6_ns_target_address=ip,
        )
        handler.send_icmp6_neighbor_solicitation_unicast.assert_not_called()

    def test__nd_cache__solicit_probe_fires_unicast_ns(self) -> None:
        """
        Ensure '_solicit_ns(addr, cached_mac=mac)' (the
        PROBE-state solicit) calls
        'send_icmp6_neighbor_solicitation_unicast(...)' — the
        unicast NS wire form that targets the cached
        neighbour directly (the IPv6 analogue of the unicast
        ARP cache-refresh probe).

        Reference: RFC 4861 §7.3.3 (unicast NS for PROBE).
        Reference: RFC 1122 §2.3.2.1 IMPL (2) (unicast ARP cache-refresh probe).
        """

        handler = MagicMock(spec=PacketHandlerL2)
        ip = Ip6Address("2001:db8::1")
        mac = MacAddress("02:00:00:00:00:01")

        self._cache._owner = handler
        self._cache._solicit_ns(ip, mac)

        handler.send_icmp6_neighbor_solicitation_unicast.assert_called_once_with(
            icmp6_ns_target_address=ip,
        )
        handler.send_icmp6_neighbor_solicitation.assert_not_called()


class TestNdCacheConstruction(_NdCacheFixture):
    """
    The 'NdCache' construction tests.
    """

    def test__nd_cache__subsystem_name(self) -> None:
        """
        Ensure the cache's Subsystem name is "ICMPv6 ND
        Cache" — matches the legacy log-channel ("nd-c") and
        the operator-visible startup banner.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._cache._subsystem_name,
            "ICMPv6 ND Cache",
            msg="NdCache must register as 'ICMPv6 ND Cache' Subsystem.",
        )

    def test__nd_cache__starts_with_empty_entry_table(self) -> None:
        """
        Ensure a freshly-constructed cache has no entries.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._cache._entries),
            0,
            msg="A fresh NdCache must have zero entries.",
        )

    def test__nd_cache__flush_callback_wired(self) -> None:
        """
        Ensure 'NdCache' constructs with its '_flush_packet'
        method as the flush_callback so a queued Ethernet
        frame parked by 'enqueue_pending' is re-emitted through
        the TX ring when a Neighbor Advertisement resolves the
        destination MAC.

        Reference: RFC 1122 §2.3.2.2 (save at least one unresolved packet).
        """

        self.assertEqual(
            self._cache._flush_callback,
            self._cache._flush_packet,
            msg="NdCache must wire '_flush_packet' as the queued-packet flush hook.",
        )

    def test__nd_cache__flush_taps_packet_sockets(self) -> None:
        """
        Ensure '_flush_packet' fans the queued-then-flushed frame to bound
        AF_PACKET sockets (via the owner's egress tap) so a frame queued
        pending ND resolution is still observed on egress, matching Linux
        'dev_queue_xmit_nit'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        eth = EthernetAssembler()
        mac = MacAddress("02:00:00:00:00:01")

        handler = MagicMock(spec=PacketHandlerL2)
        handler.tx_ring = create_autospec(TxRing, spec_set=True)
        self._cache._owner = handler
        self._cache._flush_packet(eth, mac)

        handler.deliver_tx_to_packet_sockets.assert_called_once_with(eth)
