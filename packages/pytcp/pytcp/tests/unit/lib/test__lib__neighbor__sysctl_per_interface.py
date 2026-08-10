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
Per-interface 'neighbor.*' sysctl overrides — the NUD state
machine's six runtime knobs migrate to per-interface namespaces
to match Linux's 'net.ipv4.neigh.<iface>.*' shape. Phase 2 of
the plan at 'docs/refactor/sysctl_per_interface.md'.

Two 'NeighborCache' instances stand in for "interface A" and
"interface B"; the per-iface knob '_iface_name' attribute is
the runtime read seam.

pytcp/tests/unit/lib/test__lib__neighbor__sysctl_per_interface.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, MacAddress
from pytcp.lib.neighbor import NeighborCache, NudState
from pytcp.stack import sysctl as sysctl_module

_ADDR_A = Ip4Address("10.0.0.1")
_ADDR_B = Ip4Address("10.0.0.2")
_MAC_A = MacAddress("02:00:00:00:00:01")


class _PerIfaceFixture(TestCase):
    """
    Two NeighborCache instances — one bound to '_iface_name =
    "tap_a"', the other to '"tap_b"' — let each test pin the
    per-interface read seam.
    """

    @override
    def setUp(self) -> None:
        """
        Build two caches; silence the subsystem log.
        """

        self._solicit_calls_a: list[tuple[Ip4Address, MacAddress | None]] = []
        self._solicit_calls_b: list[tuple[Ip4Address, MacAddress | None]] = []
        self._flush_calls: list[tuple[object, MacAddress]] = []

        self._log_patch = patch("pytcp.lib.neighbor.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self.addCleanup(self._subsystem_log_patch.stop)

        self._cache_a: NeighborCache[Ip4Address] = NeighborCache(
            name="Cache A",
            solicit_callback=lambda a, m: self._solicit_calls_a.append((a, m)),
            flush_callback=lambda p, m: self._flush_calls.append((p, m)),
        )
        self._cache_a._iface_name = "tap_a"
        self._cache_b: NeighborCache[Ip4Address] = NeighborCache(
            name="Cache B",
            solicit_callback=lambda a, m: self._solicit_calls_b.append((a, m)),
            flush_callback=lambda p, m: self._flush_calls.append((p, m)),
        )
        self._cache_b._iface_name = "tap_b"

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-iface mutations do not
        leak across tests.
        """

        sysctl_module.reset_to_defaults()


class TestNeighborSysctlPerInterface(_PerIfaceFixture):
    """
    The 'neighbor.<ifname>.<field>' per-interface override
    surface — six knobs migrate together.
    """

    def test__neighbor__sysctl__unres_qlen_per_iface_overrides(self) -> None:
        """
        Ensure setting 'neighbor.tap_a.unres_qlen = 2'
        constrains cache A's pending queue to two packets
        while cache B continues to honour the 'default'
        template (64) — pins the per-iface read in
        '_enqueue_pending'.

        Reference: Linux net.ipv4.neigh.<iface>.unres_qlen (per-interface queue cap).
        """

        sysctl_module.set("neighbor.tap_a.unres_qlen", 2)

        # Drive cache A — three packets through a queue
        # bounded at 2; oldest is dropped.
        p_a1, p_a2, p_a3 = object(), object(), object()
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache_a._find_entry(_ADDR_A)
            for pkt in (p_a1, p_a2, p_a3):
                self._cache_a._enqueue_pending(_ADDR_A, pkt)
            self._cache_a._add_entry(_ADDR_A, _MAC_A)

        # Cache B sees the default bound (64) and keeps all
        # three packets queued.
        p_b1, p_b2, p_b3 = object(), object(), object()
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=2000.0):
            self._cache_b._find_entry(_ADDR_B)
            for pkt in (p_b1, p_b2, p_b3):
                self._cache_b._enqueue_pending(_ADDR_B, pkt)
            self._cache_b._add_entry(_ADDR_B, _MAC_A)

        self.assertEqual(
            self._flush_calls,
            [(p_a2, _MAC_A), (p_a3, _MAC_A), (p_b1, _MAC_A), (p_b2, _MAC_A), (p_b3, _MAC_A)],
            msg=(
                "Cache A must drop its oldest packet (bound=2 per iface); "
                "cache B keeps all three (default bound=64)."
            ),
        )

    def test__neighbor__sysctl__reachable_time_per_iface_overrides(self) -> None:
        """
        Ensure setting 'neighbor.tap_a.reachable_time = 5'
        promotes cache A's entry to STALE 5 seconds after
        REACHABLE while cache B continues to honour the
        'default' 30-second template — pins the per-iface
        read in '_subsystem_loop'.

        Reference: Linux net.ipv4.neigh.<iface>.base_reachable_time_ms (per-interface NUD).
        """

        sysctl_module.set("neighbor.tap_a.reachable_time", 5)

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache_a._add_entry(_ADDR_A, _MAC_A)
            self._cache_b._add_entry(_ADDR_B, _MAC_A)

        # 6 s elapsed. Cache A's per-iface threshold (5) has
        # passed; cache B's default (30) has not.
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1006.0):
            self._cache_a._subsystem_loop()
            self._cache_b._subsystem_loop()

        self.assertIs(
            self._cache_a._entries[_ADDR_A].state,
            NudState.STALE,
            msg="Cache A must transition REACHABLE → STALE at the per-iface threshold (5 s).",
        )
        self.assertIs(
            self._cache_b._entries[_ADDR_B].state,
            NudState.REACHABLE,
            msg="Cache B with no per-iface override must stay REACHABLE under the default 30-s template.",
        )

    def test__neighbor__sysctl__base_key_write_is_rejected(self) -> None:
        """
        Ensure writing the bare base key 'neighbor.reachable_time'
        (no '<ifname>' segment) is rejected — operators MUST
        address a specific interface or the '"default"' slot.
        Pins the §4.4 contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl_module.set("neighbor.reachable_time", 5)
        self.assertIn(
            "neighbor.reachable_time",
            str(ctx.exception),
            msg="The bare-base-key rejection must surface the offending key.",
        )

    def test__neighbor__sysctl__gc_thresholds_stay_flat(self) -> None:
        """
        Ensure the four table-wide GC sysctls — 'gc_thresh1',
        'gc_thresh2', 'gc_thresh3', 'gc_stale_time' — remain
        flat (no interface scope). Linux's neighbour-table GC
        runs over the unified table; per-iface scoping would
        not match reality.

        Reference: Linux net.ipv4.neigh.default.gc_thresh{1,2,3} (table-wide).
        """

        # Flat 'set' on the bare key continues to succeed.
        sysctl_module.set("neighbor.gc_thresh1", 64)
        self.assertEqual(
            sysctl_module.get("neighbor.gc_thresh1"),
            64,
            msg="GC thresholds are table-wide; the flat key must still set.",
        )
        # Per-iface form on a flat key is rejected.
        with self.assertRaises(KeyError):
            sysctl_module.set("neighbor.tap_a.gc_thresh1", 64)
