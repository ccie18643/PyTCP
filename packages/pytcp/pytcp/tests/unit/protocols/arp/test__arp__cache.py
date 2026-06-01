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
This module contains adapter-level tests for the IPv4 ARP
cache. The full FSM behaviour (state transitions, retransmit
cadence, sysctl-driven timers, queued-packet flush semantics)
is exercised against the generic 'NeighborCache[A]' base in
'pytcp/tests/unit/lib/test__lib__neighbor.py'. This file
covers only what 'ArpCache' uniquely contributes: the IPv4-
specific solicit + flush callbacks and the kw-only public
surface ('ip4_address=', 'mac_address=',
'ethernet_packet_tx=') that legacy call sites depend on.

pytcp/tests/unit/protocols/arp/test__arp__cache.py

ver 3.0.8
"""

from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

from net_addr import Ip4Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp.lib.neighbor import NudState
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.runtime.packet_handler import PacketHandlerL2
from pytcp.runtime.tx_ring import TxRing
from pytcp.stack import sysctl as sysctl_module


class _ArpCacheFixture(TestCase):
    """
    Build a fresh ArpCache, silence subsystem logs, restore
    sysctl defaults on tearDown.
    """

    def setUp(self) -> None:
        """
        Construct cache + log patches.
        """

        self._log_patch = patch("pytcp.lib.neighbor.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self._cache = ArpCache()

    def tearDown(self) -> None:
        """
        Stop log patches and reset sysctl state.
        """

        sysctl_module.reset_to_defaults()
        self._log_patch.stop()
        self._subsystem_log_patch.stop()


class TestArpCacheKwargAPI(_ArpCacheFixture):
    """
    The kw-only 'ArpCache' public-surface tests. Pin that the
    legacy call sites (packet_handler__arp__rx,
    packet_handler__ethernet__tx) keep working — every
    method takes 'ip4_address=', 'mac_address=', or
    'ethernet_packet_tx=' as kw-only arguments and delegates
    to the generic 'NeighborCache' positional API.
    """

    def test__arp_cache__add_entry_kw_only_creates_reachable(self) -> None:
        """
        Ensure 'add_entry(ip4_address=..., mac_address=...)'
        kw-only signature creates a NUD_REACHABLE entry and
        stores the supplied MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip4Address("10.0.0.1")
        mac = MacAddress("02:00:00:00:00:01")
        self._cache.add_entry(ip4_address=ip, mac_address=mac)

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

    def test__arp_cache__find_entry_kw_only_returns_mac(self) -> None:
        """
        Ensure 'find_entry(ip4_address=...)' kw-only
        signature returns the cached MAC for a REACHABLE
        entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip4Address("10.0.0.1")
        mac = MacAddress("02:00:00:00:00:01")
        self._cache.add_entry(ip4_address=ip, mac_address=mac)

        result = self._cache.find_entry(ip4_address=ip)
        self.assertEqual(
            result,
            mac,
            msg="find_entry on a REACHABLE entry must return the cached MAC.",
        )

    def test__arp_cache__add_permanent_entry_kw_only(self) -> None:
        """
        Ensure 'add_permanent_entry(ip4_address=...,
        mac_address=...)' installs a NUD_PERMANENT entry
        which dynamic learning cannot displace.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip4Address("10.0.0.1")
        mac = MacAddress("02:00:00:00:00:01")
        other_mac = MacAddress("02:00:00:00:00:02")
        self._cache.add_permanent_entry(ip4_address=ip, mac_address=mac)
        self._cache.add_entry(ip4_address=ip, mac_address=other_mac)

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

    def test__arp_cache__confirm_reachability_kw_only(self) -> None:
        """
        Ensure 'confirm_reachability(ip4_address=...)' kw-only
        signature drives the upper-layer fastpath promotion
        on the named entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip = Ip4Address("10.0.0.1")
        mac = MacAddress("02:00:00:00:00:01")
        # Drive entry to STALE manually, then confirm.
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache.add_entry(ip4_address=ip, mac_address=mac)
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

        self._cache.confirm_reachability(ip4_address=ip)
        self.assertIs(
            self._cache._entries[ip].state,
            NudState.REACHABLE,
            msg="confirm_reachability must promote STALE → REACHABLE.",
        )

    def test__arp_cache__enqueue_pending_kw_only(self) -> None:
        """
        Ensure 'enqueue_pending(ip4_address=...,
        ethernet_packet_tx=...)' stores the packet on the
        target entry so 'add_entry' can flush it on
        resolution.

        Reference: RFC 1122 §2.3.2.2 (queued-packet semantics).
        """

        ip = Ip4Address("10.0.0.1")
        # 'find_entry' on miss creates the INCOMPLETE anchor and
        # fires the solicit callback, which routes through the
        # owning handler — bind a mock owner for the duration.
        self._cache._owner = MagicMock(spec=PacketHandlerL2)
        self._cache.find_entry(ip4_address=ip)
        # Use a real EthernetAssembler so the type guard in
        # '_flush_packet' has something genuine to dispatch.
        eth = EthernetAssembler()
        self._cache.enqueue_pending(ip4_address=ip, ethernet_packet_tx=eth)

        self.assertEqual(
            list(self._cache._entries[ip].queued_packets),
            [eth],
            msg="enqueue_pending must append the packet to the INCOMPLETE entry's pending queue.",
        )


class TestArpCacheSolicitCallback(_ArpCacheFixture):
    """
    The wire-level solicit-callback tests — what the FSM
    asks the protocol-specific layer to send.
    """

    def test__arp_cache__solicit_incomplete_fires_broadcast_request(self) -> None:
        """
        Ensure '_solicit_arp(addr, cached_mac=None)' (the
        INCOMPLETE-state solicit) calls
        'stack.packet_handler.send_arp_request(arp__tpa=addr)'
        — the broadcast Request form for first-resolution
        attempts.

        Reference: RFC 826 (broadcast ARP Request on cache miss).
        """

        handler = MagicMock(spec=PacketHandlerL2)
        ip = Ip4Address("10.0.0.1")

        self._cache._owner = handler
        self._cache._solicit_arp(ip, None)

        handler.send_arp_request.assert_called_once_with(arp__tpa=ip)
        handler.send_arp_unicast_request.assert_not_called()

    def test__arp_cache__solicit_probe_fires_unicast_request(self) -> None:
        """
        Ensure '_solicit_arp(addr, cached_mac=mac)' (the
        PROBE-state solicit) calls
        'send_arp_unicast_request(arp__tpa=addr,
        ethernet__dst=mac)' — the unicast cache-refresh
        probe form.

        Reference: RFC 1122 §2.3.2.1 IMPL (2) (unicast cache-refresh probe).
        """

        handler = MagicMock(spec=PacketHandlerL2)
        ip = Ip4Address("10.0.0.1")
        mac = MacAddress("02:00:00:00:00:01")

        self._cache._owner = handler
        self._cache._solicit_arp(ip, mac)

        handler.send_arp_unicast_request.assert_called_once_with(
            arp__tpa=ip,
            ethernet__dst=mac,
        )
        handler.send_arp_request.assert_not_called()


class TestArpCacheFlushCallback(_ArpCacheFixture):
    """
    The wire-level flush-callback tests — what the FSM does
    with a queued packet on resolution.
    """

    def test__arp_cache__flush_rewrites_dst_and_enqueues(self) -> None:
        """
        Ensure '_flush_packet(packet, mac)' rewrites the
        Ethernet destination MAC on the queued frame and
        dispatches it through the owning interface handler's TX
        ring — the post-resolution delivery side of the
        queued-packet contract.

        Reference: RFC 1122 §2.3.2.2 (transmit saved packet on resolution).
        """

        eth = EthernetAssembler()
        mac = MacAddress("02:00:00:00:00:01")

        handler = MagicMock(spec=PacketHandlerL2)
        tx_ring = create_autospec(TxRing, spec_set=True)
        handler._tx_ring = tx_ring
        self._cache._owner = handler
        self._cache._flush_packet(eth, mac)

        self.assertEqual(
            eth.dst,
            mac,
            msg="_flush_packet must rewrite the Ethernet destination MAC.",
        )
        tx_ring.enqueue.assert_called_once_with(eth)


class TestArpCacheConstruction(_ArpCacheFixture):
    """
    The 'ArpCache' construction tests.
    """

    def test__arp_cache__subsystem_name(self) -> None:
        """
        Ensure the cache's Subsystem name is "ARP Cache" —
        matches the legacy log-channel ("arp-c") and the
        operator-visible startup banner.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._cache._subsystem_name,
            "ARP Cache",
            msg="ArpCache must register as 'ARP Cache' Subsystem.",
        )

    def test__arp_cache__starts_with_empty_entry_table(self) -> None:
        """
        Ensure a freshly-constructed cache has no entries.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._cache._entries),
            0,
            msg="A fresh ArpCache must have zero entries.",
        )
