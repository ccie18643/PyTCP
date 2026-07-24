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
This module contains tests for the 'pytcp.lib.neighbor'
generic NeighborCache[A] FSM — Phase 1 of the NUD migration
plan at 'docs/refactor/nud_state_machine.md'.

pytcp/tests/unit/lib/test__lib__neighbor.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, MacAddress

# Trigger the constants module import so its sysctl
# registrations land before the tests construct caches /
# patch values.
from pytcp.lib import neighbor__constants  # noqa: F401
from pytcp.lib.neighbor import NeighborCache, NeighborEntry, NudState
from pytcp.stack import sysctl as sysctl_module

# Test addresses — using IPv4 since the FSM is identical
# across IPv4/IPv6 and Ip4Address keeps fixtures concise.
ADDR_A = Ip4Address("10.0.0.1")
ADDR_B = Ip4Address("10.0.0.2")
MAC_A = MacAddress("02:00:00:00:00:01")
MAC_B = MacAddress("02:00:00:00:00:02")


class _NeighborCacheFixture(TestCase):
    """
    Shared fixture: build a cache with recorder callbacks and
    a controllable monotonic clock. Every test enters with the
    sysctl defaults and exits restoring them via 'reset_to_defaults'
    so per-test overrides do not leak.
    """

    @override
    def setUp(self) -> None:
        """
        Build the cache with spy callbacks for solicit and flush.
        """

        self._solicit_calls: list[tuple[Ip4Address, MacAddress | None]] = []
        self._flush_calls: list[tuple[object, MacAddress]] = []

        # Patch the subsystem 'log' before constructing so the
        # noisy initialise log does not pollute test output.
        self._log_patch = patch("pytcp.lib.neighbor.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()

        self._cache: NeighborCache[Ip4Address] = NeighborCache(
            name="Test Neighbor Cache",
            solicit_callback=self._record_solicit,
            flush_callback=self._record_flush,
        )

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults and remove log patches.
        """

        sysctl_module.reset_to_defaults()
        self._log_patch.stop()
        self._subsystem_log_patch.stop()

    def _record_solicit(self, address: Ip4Address, cached_mac: MacAddress | None) -> None:
        """
        Spy: append every solicit invocation for assertion.
        """

        self._solicit_calls.append((address, cached_mac))

    def _record_flush(self, packet: object, mac: MacAddress) -> None:
        """
        Spy: append every queued-packet flush for assertion.
        """

        self._flush_calls.append((packet, mac))

    def _run_loop_once(self, *, now: float) -> None:
        """
        Run a single iteration of '_subsystem_loop' with the
        monotonic clock pinned to 'now'. The 'wait' patch
        prevents the inter-iteration sleep from delaying tests.
        """

        with (
            patch("pytcp.lib.neighbor.time.monotonic", return_value=now),
            patch.object(self._cache._event__stop_subsystem, "wait", return_value=False),
        ):
            self._cache._subsystem_loop()


class TestNeighborCacheFindMiss(_NeighborCacheFixture):
    """
    The 'find_entry' cache-miss path tests.
    """

    def test__lib__neighbor__find_miss_creates_incomplete_entry(self) -> None:
        """
        Ensure 'find_entry' on an unknown address creates a
        new entry in NUD_INCOMPLETE state — the entry is the
        anchor for queued packets and the retransmit counter
        the loop uses to decide when to give up.

        Reference: RFC 4861 §7.3.2 (NUD INCOMPLETE on resolution miss).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            result = self._cache._find_entry(ADDR_A)

        self.assertIsNone(
            result,
            msg="find_entry on a miss must return None — the MAC is not yet known.",
        )
        self.assertIn(
            ADDR_A,
            self._cache._entries,
            msg="find_entry on a miss must create an entry as the anchor for retransmits.",
        )
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.INCOMPLETE,
            msg="A freshly-created entry on a miss must be in NUD_INCOMPLETE state.",
        )

    def test__lib__neighbor__find_miss_fires_multicast_solicit(self) -> None:
        """
        Ensure 'find_entry' on a miss fires the
        solicit_callback with 'cached_mac=None' — the wire
        signal to the protocol-specific TX layer that this
        is the INCOMPLETE / first-resolution case
        (multicast NS for ND, broadcast Request for ARP).

        Reference: RFC 4861 §7.2.2 (multicast NS for INCOMPLETE).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)

        self.assertEqual(
            self._solicit_calls,
            [(ADDR_A, None)],
            msg=(
                "find_entry on a miss must fire solicit_callback with "
                "cached_mac=None to drive a multicast/broadcast solicit."
            ),
        )

    def test__lib__neighbor__find_repeated_within_retrans_no_new_solicit(self) -> None:
        """
        Ensure a second 'find_entry' for the same INCOMPLETE
        address within RETRANS_TIMER seconds does NOT fire a
        new solicit — the loop's retransmit cadence (gated
        by RETRANS_TIMER) is the single source of truth for
        re-solicits while INCOMPLETE.

        Reference: RFC 4861 §7.2.2 (RETRANS_TIMER spaces solicits).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
            self._cache._find_entry(ADDR_A)

        self.assertEqual(
            len(self._solicit_calls),
            1,
            msg=(
                "Two find_entry calls on the same INCOMPLETE address must produce "
                "exactly one solicit; the loop's RETRANS_TIMER drives any retries."
            ),
        )


class TestNeighborCacheAddEntry(_NeighborCacheFixture):
    """
    The 'add_entry' (Reply received) tests.
    """

    def test__lib__neighbor__add_entry_transitions_incomplete_to_reachable(self) -> None:
        """
        Ensure 'add_entry' on an INCOMPLETE entry transitions
        it to NUD_REACHABLE and stores the resolved MAC. A
        subsequent 'find_entry' returns the MAC immediately
        without firing a new solicit.

        Reference: RFC 4861 §7.3.2 (INCOMPLETE → REACHABLE on solicited Reply).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
            self._cache._add_entry(ADDR_A, MAC_A)

        entry = self._cache._entries[ADDR_A]
        self.assertIs(
            entry.state,
            NudState.REACHABLE,
            msg="add_entry must transition the entry to NUD_REACHABLE.",
        )
        self.assertEqual(
            entry.mac_address,
            MAC_A,
            msg="add_entry must store the resolved MAC on the entry.",
        )

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1001.0):
            result = self._cache._find_entry(ADDR_A)
        self.assertEqual(
            result,
            MAC_A,
            msg="find_entry on a REACHABLE entry must return the cached MAC.",
        )
        self.assertEqual(
            len(self._solicit_calls),
            1,
            msg="A REACHABLE-state find_entry must NOT fire a new solicit.",
        )

    def test__lib__neighbor__add_entry_creates_reachable_when_no_prior_entry(self) -> None:
        """
        Ensure 'add_entry' for an address with no prior
        cache entry creates a new REACHABLE entry directly —
        gratuitous-ARP / unsolicited-NA learning path.

        Reference: RFC 4861 §7.2.5 (unsolicited NA learning).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.REACHABLE,
            msg="Unsolicited add_entry must create a fresh REACHABLE entry.",
        )

    def test__lib__neighbor__add_entry_flushes_queued_packet(self) -> None:
        """
        Ensure 'add_entry' on an INCOMPLETE entry with a
        queued packet flushes the packet via flush_callback
        once the MAC is resolved — the link-layer queue
        semantics generalised across address families.

        Reference: RFC 1122 §2.3.2.2 (save unresolved packet, transmit on resolution).
        """

        sentinel_packet = object()

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
            self._cache._enqueue_pending(ADDR_A, sentinel_packet)
            self._cache._add_entry(ADDR_A, MAC_A)

        self.assertEqual(
            self._flush_calls,
            [(sentinel_packet, MAC_A)],
            msg=(
                "add_entry must flush the queued packet via flush_callback "
                "once the MAC is resolved; the cache passes the packet and "
                "the resolved MAC to the protocol-specific flush hook."
            ),
        )

    def test__lib__neighbor__add_entry_no_flush_when_no_queued_packet(self) -> None:
        """
        Ensure 'add_entry' on an INCOMPLETE entry without a
        queued packet does NOT call flush_callback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
            self._cache._add_entry(ADDR_A, MAC_A)

        self.assertEqual(
            self._flush_calls,
            [],
            msg="No flush_callback should fire when no packet was queued.",
        )

    def test__lib__neighbor__add_entry_overrides_permanent_skipped(self) -> None:
        """
        Ensure 'add_entry' on a PERMANENT entry does NOT
        override the cached MAC — permanent entries are
        operator-configured static neighbours that dynamic
        ARP / ND learning must not displace.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_permanent_entry(ADDR_A, MAC_A)
            self._cache._add_entry(ADDR_A, MAC_B)

        entry = self._cache._entries[ADDR_A]
        self.assertEqual(
            entry.mac_address,
            MAC_A,
            msg="add_entry must NOT overwrite the MAC of a PERMANENT entry.",
        )
        self.assertIs(
            entry.state,
            NudState.PERMANENT,
            msg="The entry must remain PERMANENT after a dynamic add_entry attempt.",
        )


class TestNeighborCacheReachableToStale(_NeighborCacheFixture):
    """
    The REACHABLE → STALE timer-driven transition tests.
    """

    def test__lib__neighbor__reachable_transitions_to_stale_after_reachable_time(self) -> None:
        """
        Ensure the loop transitions a REACHABLE entry to STALE
        once REACHABLE_TIME has elapsed since the last
        confirmation. STALE means "still believed to be the
        right MAC, but worth confirming on the next TX."

        Reference: RFC 4861 §7.3.3 (REACHABLE_TIME aging).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        # REACHABLE_TIME default is 30 s; advance to 1000 + 31.
        self._run_loop_once(now=1031.0)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.STALE,
            msg="REACHABLE entry past REACHABLE_TIME must transition to STALE.",
        )

    def test__lib__neighbor__reachable_within_window_unchanged(self) -> None:
        """
        Ensure a REACHABLE entry whose age is BELOW
        REACHABLE_TIME is left in REACHABLE — the loop must
        not transition early.

        Reference: RFC 4861 §7.3.3 (timer is hard floor).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        # 5 s elapsed, well below the 30 s default.
        self._run_loop_once(now=1005.0)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.REACHABLE,
            msg="REACHABLE entry within REACHABLE_TIME must NOT transition.",
        )


class TestNeighborCacheStaleToDelay(_NeighborCacheFixture):
    """
    The STALE → DELAY on-TX transition tests.
    """

    def test__lib__neighbor__find_on_stale_transitions_to_delay_returns_mac(self) -> None:
        """
        Ensure 'find_entry' on a STALE entry returns the
        cached MAC AND transitions the entry to NUD_DELAY —
        DELAY is the grace period before sending a unicast
        probe; if upper-layer traffic confirms reachability
        during this window, we skip the probe.

        Reference: RFC 4861 §7.3.3 (STALE → DELAY on packet send).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        self._run_loop_once(now=1031.0)
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.STALE,
            msg="Pre-condition: entry must be STALE before the TX-driven transition.",
        )

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1031.5):
            result = self._cache._find_entry(ADDR_A)

        self.assertEqual(
            result,
            MAC_A,
            msg="find_entry on STALE must still return the cached MAC.",
        )
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.DELAY,
            msg="find_entry on STALE must transition the entry to NUD_DELAY.",
        )


class TestNeighborCacheDelayToProbe(_NeighborCacheFixture):
    """
    The DELAY → PROBE timer-driven transition tests.
    """

    def test__lib__neighbor__delay_transitions_to_probe_after_delay_first_probe_time(self) -> None:
        """
        Ensure the loop transitions a DELAY entry to PROBE
        after DELAY_FIRST_PROBE_TIME has elapsed without an
        upper-layer reachability confirmation, AND fires a
        unicast solicit (cached_mac is set).

        Reference: RFC 4861 §7.3.3 (DELAY → PROBE on timer).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        self._run_loop_once(now=1031.0)  # → STALE

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1031.5):
            self._cache._find_entry(ADDR_A)  # → DELAY
        self._solicit_calls.clear()

        # DELAY_FIRST_PROBE_TIME default = 5 s.
        self._run_loop_once(now=1031.5 + 5.5)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.PROBE,
            msg="DELAY entry past DELAY_FIRST_PROBE_TIME must transition to PROBE.",
        )
        self.assertEqual(
            self._solicit_calls,
            [(ADDR_A, MAC_A)],
            msg=(
                "DELAY → PROBE transition must fire solicit_callback with "
                "cached_mac=MAC_A — unicast probe to the cached neighbour."
            ),
        )


class TestNeighborCacheProbeToFailed(_NeighborCacheFixture):
    """
    The PROBE retransmit and PROBE → FAILED tests.
    """

    def test__lib__neighbor__probe_retransmits_at_retrans_timer_cadence(self) -> None:
        """
        Ensure the loop re-fires the unicast solicit each
        RETRANS_TIMER seconds while in PROBE state, until
        MAX_UNICAST_SOLICIT retries have been issued.

        Reference: RFC 4861 §7.3.3 (PROBE retransmits at RETRANS_TIMER).
        """

        # Drive entry into PROBE state.
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        self._run_loop_once(now=1031.0)
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1031.5):
            self._cache._find_entry(ADDR_A)
        self._run_loop_once(now=1037.5)  # DELAY → PROBE; one solicit fired.
        self._solicit_calls.clear()

        # RETRANS_TIMER default = 1 s; advance through two more retries.
        self._run_loop_once(now=1038.6)
        self._run_loop_once(now=1039.7)

        # MAX_UNICAST_SOLICIT default = 3, of which one fired on
        # the DELAY → PROBE transition; two more here = three total.
        self.assertEqual(
            len(self._solicit_calls),
            2,
            msg=(
                "After two further retrans intervals, two more PROBE solicits "
                f"must have fired. Got: {len(self._solicit_calls)}"
            ),
        )

    def test__lib__neighbor__probe_transitions_to_failed_after_max_unicast_solicit(self) -> None:
        """
        Ensure PROBE transitions to FAILED after
        MAX_UNICAST_SOLICIT unicast probes have gone
        unanswered. A FAILED entry is no longer eligible for
        TX use ('find_entry' returns None) but persists for
        observability until GC removes it.

        Reference: RFC 4861 §7.3.3 (PROBE → FAILED after retries).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        self._run_loop_once(now=1031.0)  # → STALE
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1031.5):
            self._cache._find_entry(ADDR_A)  # → DELAY
        self._run_loop_once(now=1037.5)  # DELAY → PROBE, probe_count=1

        # Two more retransmits, then one more loop pass to
        # detect probe_count >= MAX_UNICAST_SOLICIT.
        self._run_loop_once(now=1038.6)  # probe_count=2
        self._run_loop_once(now=1039.7)  # probe_count=3
        self._run_loop_once(now=1040.8)  # check → FAILED

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.FAILED,
            msg="PROBE entry past MAX_UNICAST_SOLICIT retries must transition to FAILED.",
        )

    def test__lib__neighbor__find_on_failed_returns_none(self) -> None:
        """
        Ensure 'find_entry' on a FAILED entry returns None
        without firing a new solicit — the FSM has given up
        and a fresh resolution attempt requires explicit
        eviction (Phase 5 GC) followed by a new find.

        Reference: RFC 4861 §7.3.3 (FAILED gates new TX).
        """

        # Drive entry into FAILED state by short-circuiting.
        self._cache._entries[ADDR_A] = NeighborEntry(
            address=ADDR_A,
            mac_address=MAC_A,
            state=NudState.FAILED,
            state_changed_at=1000.0,
        )

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1010.0):
            result = self._cache._find_entry(ADDR_A)

        self.assertIsNone(
            result,
            msg="find_entry on FAILED must return None (the FSM has given up).",
        )
        self.assertEqual(
            self._solicit_calls,
            [],
            msg="find_entry on FAILED must NOT fire a new solicit.",
        )


class TestNeighborCacheProbeToReachable(_NeighborCacheFixture):
    """
    The PROBE → REACHABLE on-Reply transition tests.
    """

    def test__lib__neighbor__add_entry_in_probe_returns_to_reachable(self) -> None:
        """
        Ensure 'add_entry' on a PROBE entry returns it to
        REACHABLE and resets probe_count — a successful
        unicast probe Reply confirms the neighbour is alive.

        Reference: RFC 4861 §7.3.3 (PROBE → REACHABLE on Reply).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        self._run_loop_once(now=1031.0)
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1031.5):
            self._cache._find_entry(ADDR_A)
        self._run_loop_once(now=1037.5)
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.PROBE,
            msg="Pre-condition: entry must be PROBE before the Reply.",
        )

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1038.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        entry = self._cache._entries[ADDR_A]
        self.assertIs(
            entry.state,
            NudState.REACHABLE,
            msg="add_entry on PROBE must return the entry to REACHABLE.",
        )
        self.assertEqual(
            entry.probe_count,
            0,
            msg="add_entry on PROBE must reset probe_count for the next aging cycle.",
        )


class TestNeighborCacheConfirmReachability(_NeighborCacheFixture):
    """
    The 'confirm_reachability' upper-layer hook tests.
    """

    def test__lib__neighbor__confirm_on_stale_promotes_to_reachable(self) -> None:
        """
        Ensure 'confirm_reachability' on a STALE entry
        promotes it directly to REACHABLE without firing a
        unicast probe — upper-layer evidence (e.g. in-window
        TCP ACK) is stronger than a probe Reply.

        Reference: RFC 4861 §7.3.1 (upper-layer reachability confirmation).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        self._run_loop_once(now=1031.0)
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.STALE,
            msg="Pre-condition: entry must be STALE before the confirm.",
        )

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1032.0):
            self._cache._confirm_reachability(ADDR_A)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.REACHABLE,
            msg="confirm_reachability on STALE must promote to REACHABLE.",
        )

    def test__lib__neighbor__confirm_on_delay_promotes_to_reachable(self) -> None:
        """
        Ensure 'confirm_reachability' on a DELAY entry
        promotes it to REACHABLE — the upper-layer evidence
        cancels the impending PROBE transition.

        Reference: RFC 4861 §7.3.1 (DELAY upper-layer fastpath).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        self._run_loop_once(now=1031.0)
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1031.5):
            self._cache._find_entry(ADDR_A)
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.DELAY,
            msg="Pre-condition: entry must be DELAY before the confirm.",
        )

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1032.0):
            self._cache._confirm_reachability(ADDR_A)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.REACHABLE,
            msg="confirm_reachability on DELAY must promote to REACHABLE.",
        )

    def test__lib__neighbor__confirm_on_incomplete_no_op(self) -> None:
        """
        Ensure 'confirm_reachability' on an INCOMPLETE entry
        is a no-op — there is no MAC yet, so an upper-layer
        confirm cannot transition the entry to REACHABLE.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
            self._cache._confirm_reachability(ADDR_A)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.INCOMPLETE,
            msg="confirm_reachability on INCOMPLETE must NOT promote to REACHABLE.",
        )

    def test__lib__neighbor__confirm_on_unknown_no_op(self) -> None:
        """
        Ensure 'confirm_reachability' on an unknown address
        is a silent no-op — TCP layer can call this on any
        peer without first checking the cache, and absent
        entries simply produce no effect (no spurious
        cache-population).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._confirm_reachability(ADDR_A)

        self.assertNotIn(
            ADDR_A,
            self._cache._entries,
            msg="confirm_reachability on unknown address must NOT create an entry.",
        )


class TestNeighborCachePermanent(_NeighborCacheFixture):
    """
    The PERMANENT-state tests.
    """

    def test__lib__neighbor__permanent_skips_all_aging(self) -> None:
        """
        Ensure a PERMANENT entry never transitions to STALE
        regardless of how much time has elapsed — the entry
        is operator-configured static neighbour state and the
        cache's aging logic must respect it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_permanent_entry(ADDR_A, MAC_A)

        # Advance well past REACHABLE_TIME.
        self._run_loop_once(now=1_000_000.0)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.PERMANENT,
            msg="PERMANENT entry must NOT transition to STALE regardless of age.",
        )


class TestNeighborCacheIncompleteRetransmits(_NeighborCacheFixture):
    """
    The INCOMPLETE retransmit + INCOMPLETE → FAILED tests.
    """

    def test__lib__neighbor__incomplete_retransmits_at_retrans_timer(self) -> None:
        """
        Ensure the loop re-fires the multicast/broadcast
        solicit each RETRANS_TIMER seconds while in
        INCOMPLETE state, until MAX_MULTICAST_SOLICIT retries
        have been issued.

        Reference: RFC 4861 §7.2.2 (INCOMPLETE retransmit cadence).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)  # initial solicit
        self._solicit_calls.clear()

        self._run_loop_once(now=1001.5)
        self._run_loop_once(now=1002.6)

        self.assertEqual(
            len(self._solicit_calls),
            2,
            msg=(
                "After two RETRANS_TIMER intervals, two multicast solicits must "
                f"have fired. Got: {len(self._solicit_calls)}"
            ),
        )
        for addr, mac in self._solicit_calls:
            self.assertEqual(addr, ADDR_A, msg="Solicit address must match.")
            self.assertIsNone(
                mac,
                msg="INCOMPLETE-state retransmits must use cached_mac=None (multicast/broadcast).",
            )

    def test__lib__neighbor__incomplete_transitions_to_failed_after_max_multicast_solicit(self) -> None:
        """
        Ensure INCOMPLETE transitions to FAILED after
        MAX_MULTICAST_SOLICIT solicits have gone unanswered
        — gives up the resolution attempt.

        Reference: RFC 4861 §7.2.2 (INCOMPLETE → FAILED after retries).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
        # MAX_MULTICAST_SOLICIT default = 3 — initial + 2 retries
        # then loop pass detects the cap.
        self._run_loop_once(now=1001.5)
        self._run_loop_once(now=1002.6)
        self._run_loop_once(now=1003.7)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.FAILED,
            msg="INCOMPLETE entry past MAX_MULTICAST_SOLICIT must transition to FAILED.",
        )


class TestNeighborCacheSysctlOverrides(_NeighborCacheFixture):
    """
    The sysctl-driven knob override tests.
    """

    def test__lib__neighbor__reachable_time_sysctl_override_honoured(self) -> None:
        """
        Ensure 'pytcp.stack.sysctl["neighbor.reachable_time"]'
        overrides the REACHABLE → STALE timer at runtime —
        the cache reads the live value via qualified access
        on each loop iteration.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl_module.override("neighbor.default.reachable_time", 5):
            with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
                self._cache._add_entry(ADDR_A, MAC_A)

            # 6 s elapsed (above override of 5).
            self._run_loop_once(now=1006.0)

            self.assertIs(
                self._cache._entries[ADDR_A].state,
                NudState.STALE,
                msg=(
                    "REACHABLE → STALE must trigger at the overridden 5-second "
                    "reachable_time, not the 30-second default."
                ),
            )

        # After context-exit the default is restored.
        self.assertEqual(
            neighbor__constants.NEIGHBOR__REACHABLE_TIME["default"],
            30,
            msg="Override must restore the default on context exit.",
        )


class TestNeighborCacheGcPass(_NeighborCacheFixture):
    """
    The bounded-cache GC tests (Phase 5 of the NUD plan).

    Pin the three-tier eviction policy: below 'gc_thresh1'
    no-op, above 'gc_thresh2' evict FAILED + stale-past-
    'gc_stale_time' STALE, above 'gc_thresh3' hard cap forces
    LRU eviction. PERMANENT entries and INCOMPLETE entries
    holding a queued packet are never evicted regardless of
    cache size.
    """

    def _populate(self, count: int, *, base: int = 1) -> list[Ip4Address]:
        """
        Bulk-populate the cache with REACHABLE entries at
        sequential addresses. Returns the list of addresses
        in insertion order.
        """

        addrs = [Ip4Address(f"10.0.{i // 256}.{i % 256}") for i in range(base, base + count)]
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            for a in addrs:
                self._cache._add_entry(a, MAC_A)
        return addrs

    def _force_state(self, address: Ip4Address, state: NudState, *, when: float = 1000.0) -> None:
        """
        Drop an entry into the named state at a specific
        'state_changed_at'. Bypasses the FSM transitions to
        keep test setup tight.
        """

        entry = self._cache._entries[address]
        object.__setattr__(entry, "state", state)
        object.__setattr__(entry, "state_changed_at", when)

    def test__lib__neighbor__gc_below_thresh1_is_no_op(self) -> None:
        """
        Ensure a cache populated below 'gc_thresh1' is left
        intact by the GC pass — small caches never collect.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl_module.override("neighbor.gc_thresh1", 10):
            self._populate(5)
            self._cache._gc_pass(now=2000.0)

            self.assertEqual(
                len(self._cache._entries),
                5,
                msg="GC must NOT evict any entry while size <= gc_thresh1.",
            )

    def test__lib__neighbor__gc_evicts_failed_above_thresh1(self) -> None:
        """
        Ensure the GC pass evicts FAILED entries first when
        cache size crosses 'gc_thresh1'. FAILED is the
        cheapest eviction — no working neighbour to lose.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl_module.override("neighbor.gc_thresh1", 2):
            addrs = self._populate(5)
            # Mark addrs[0] and addrs[1] as FAILED.
            self._force_state(addrs[0], NudState.FAILED)
            self._force_state(addrs[1], NudState.FAILED)

            self._cache._gc_pass(now=2000.0)

            self.assertNotIn(
                addrs[0],
                self._cache._entries,
                msg="FAILED entry must be evicted by GC above gc_thresh1.",
            )
            self.assertNotIn(
                addrs[1],
                self._cache._entries,
                msg="FAILED entry must be evicted by GC above gc_thresh1.",
            )
            self.assertEqual(
                len(self._cache._entries),
                3,
                msg="Only FAILED entries must be evicted at this tier; REACHABLE survive.",
            )

    def test__lib__neighbor__gc_evicts_stale_past_stale_time_above_thresh2(self) -> None:
        """
        Ensure STALE entries that have aged past
        'gc_stale_time' become eviction-eligible once cache
        size crosses 'gc_thresh2', and the OLDEST go first.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            sysctl_module.override("neighbor.gc_thresh1", 0),
            sysctl_module.override("neighbor.gc_thresh2", 2),
            sysctl_module.override("neighbor.gc_stale_time", 60),
        ):
            addrs = self._populate(5)
            # Two old STALE entries, two recent STALE entries,
            # one REACHABLE.
            self._force_state(addrs[0], NudState.STALE, when=1000.0)
            self._force_state(addrs[1], NudState.STALE, when=1100.0)
            self._force_state(addrs[2], NudState.STALE, when=1980.0)
            self._force_state(addrs[3], NudState.STALE, when=1990.0)
            # addrs[4] stays REACHABLE.

            # 'now' = 2000 → addrs[0] / [1] are 1000 / 900s
            # stale (>60), addrs[2] / [3] are 20 / 10s stale
            # (<60). Cache size 5 > gc_thresh2 (2) → eligible
            # to evict 3 entries (5-2). Only 2 are aged past
            # gc_stale_time, so only those 2 evict. Net size
            # 5 → 3.
            self._cache._gc_pass(now=2000.0)

            self.assertNotIn(
                addrs[0],
                self._cache._entries,
                msg="Oldest stale entry must be evicted first.",
            )
            self.assertNotIn(
                addrs[1],
                self._cache._entries,
                msg="Second-oldest stale entry must be evicted next.",
            )
            self.assertIn(
                addrs[2],
                self._cache._entries,
                msg="Recent stale entry (within gc_stale_time) must NOT be evicted.",
            )
            self.assertIn(
                addrs[3],
                self._cache._entries,
                msg="Recent stale entry (within gc_stale_time) must NOT be evicted.",
            )
            self.assertIn(
                addrs[4],
                self._cache._entries,
                msg="REACHABLE entry must NOT be evicted at gc_thresh2 tier.",
            )

    def test__lib__neighbor__gc_hard_cap_evicts_lru_above_thresh3(self) -> None:
        """
        Ensure that above 'gc_thresh3', the GC pass evicts in
        LRU order (oldest 'last_used_at' first) — including
        REACHABLE entries — until size <= gc_thresh3. The
        hard cap is a MUST.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            sysctl_module.override("neighbor.gc_thresh1", 0),
            sysctl_module.override("neighbor.gc_thresh2", 0),
            sysctl_module.override("neighbor.gc_thresh3", 3),
        ):
            addrs = self._populate(5)
            # Vary last_used_at to set LRU order.
            for i, a in enumerate(addrs):
                object.__setattr__(self._cache._entries[a], "last_used_at", 1000.0 + i)
            # addrs[0] is least-recently-used; addrs[4] most.

            self._cache._gc_pass(now=2000.0)

            self.assertEqual(
                len(self._cache._entries),
                3,
                msg="Hard cap must reduce cache size to gc_thresh3.",
            )
            self.assertNotIn(
                addrs[0],
                self._cache._entries,
                msg="Least-recently-used entry must be evicted first by hard cap.",
            )
            self.assertNotIn(
                addrs[1],
                self._cache._entries,
                msg="Second-LRU entry must be evicted by hard cap.",
            )
            self.assertIn(
                addrs[4],
                self._cache._entries,
                msg="Most-recently-used entry must survive the hard cap.",
            )

    def test__lib__neighbor__gc_skips_permanent_entries(self) -> None:
        """
        Ensure PERMANENT entries are never evicted regardless
        of cache size, GC tier, or how stale they look.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            sysctl_module.override("neighbor.gc_thresh1", 0),
            sysctl_module.override("neighbor.gc_thresh3", 0),
        ):
            with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
                self._cache._add_permanent_entry(ADDR_A, MAC_A)
                self._cache._add_entry(ADDR_B, MAC_B)
            # Force the dynamic entry to STALE so it gets
            # picked up by tier 2.
            self._force_state(ADDR_B, NudState.STALE, when=1000.0)

            self._cache._gc_pass(now=2000.0)

            self.assertIn(
                ADDR_A,
                self._cache._entries,
                msg="PERMANENT entry must NOT be evicted by GC at any tier.",
            )

    def test__lib__neighbor__gc_skips_entries_with_queued_packet(self) -> None:
        """
        Ensure entries holding a queued packet (INCOMPLETE
        with a TX waiting for resolution) are NOT evicted —
        evicting would lose the queued frame and break the
        link-layer-queue contract.

        Reference: RFC 1122 §2.3.2.2 (queued-packet preservation).
        """

        with (
            sysctl_module.override("neighbor.gc_thresh1", 0),
            sysctl_module.override("neighbor.gc_thresh3", 0),
        ):
            with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
                self._cache._find_entry(ADDR_A)  # → INCOMPLETE
                self._cache._enqueue_pending(ADDR_A, packet=object())

            # Drive the entry to FAILED while keeping the
            # queued_packet — represents the worst case
            # (resolution gave up, but a packet is still
            # held).
            self._force_state(ADDR_A, NudState.FAILED)

            self._cache._gc_pass(now=2000.0)

            self.assertIn(
                ADDR_A,
                self._cache._entries,
                msg=(
                    "Entry with queued_packet must NOT be evicted; doing so "
                    "would lose the queued TX. RFC 1122 §2.3.2.2."
                ),
            )

    def test__lib__neighbor__gc_no_op_at_exact_thresh1(self) -> None:
        """
        Ensure the GC pass is a no-op when cache size equals
        gc_thresh1 exactly (the '<= gc_thresh1' return is inclusive),
        even with a FAILED entry present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl_module.override("neighbor.gc_thresh1", 3):
            addrs = self._populate(3)  # size == gc_thresh1
            self._force_state(addrs[0], NudState.FAILED)

            self._cache._gc_pass(now=2000.0)

            self.assertIn(
                addrs[0],
                self._cache._entries,
                msg="At size == gc_thresh1 the GC must NOT evict (inclusive boundary).",
            )

    def test__lib__neighbor__gc_does_not_enter_stale_tier_at_exact_thresh2(self) -> None:
        """
        Ensure the STALE-eviction tier is NOT entered when, after the
        FAILED tier, cache size equals gc_thresh2 exactly (the
        'size > gc_thresh2' gate is strict).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            sysctl_module.override("neighbor.gc_thresh1", 0),
            sysctl_module.override("neighbor.gc_thresh2", 3),
            sysctl_module.override("neighbor.gc_thresh3", 1000),
            sysctl_module.override("neighbor.gc_stale_time", 60),
        ):
            addrs = self._populate(3)  # size == gc_thresh2, no FAILED to prune
            # An old STALE entry that WOULD be evicted if the tier ran.
            self._force_state(addrs[0], NudState.STALE, when=1000.0)

            self._cache._gc_pass(now=2000.0)

            self.assertIn(
                addrs[0],
                self._cache._entries,
                msg="At size == gc_thresh2 the STALE tier must NOT run (strict '>').",
            )

    def test__lib__neighbor__gc_does_not_enter_lru_tier_at_exact_thresh3(self) -> None:
        """
        Ensure the hard-cap LRU tier is NOT entered when, after the
        FAILED / STALE tiers, cache size equals gc_thresh3 exactly
        (the 'size > gc_thresh3' gate is strict).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            sysctl_module.override("neighbor.gc_thresh1", 0),
            sysctl_module.override("neighbor.gc_thresh2", 1000),
            sysctl_module.override("neighbor.gc_thresh3", 3),
        ):
            addrs = self._populate(3)  # size == gc_thresh3, all REACHABLE

            self._cache._gc_pass(now=2000.0)

            self.assertEqual(
                len(self._cache._entries),
                3,
                msg="At size == gc_thresh3 the LRU hard-cap tier must NOT evict (strict '>').",
            )
            self.assertIn(
                addrs[0],
                self._cache._entries,
                msg="No REACHABLE entry may be LRU-evicted at exactly gc_thresh3.",
            )


class TestNeighborCachePendingQueue(_NeighborCacheFixture):
    """
    The RFC 1122 §2.3.2.2 bounded pending-packet queue
    (Linux 'neigh->arp_queue' semantics).
    """

    def test__lib__neighbor__pending_queue_flushes_all_in_fifo_order(self) -> None:
        """
        Ensure every packet queued against an unresolved
        neighbour is delivered, in arrival order, once the MAC
        resolves — not just the most recent one (a fragmented
        datagram is several link-layer packets).

        Reference: RFC 1122 §2.3.2.2 (save unresolved packets, transmit on resolution).
        """

        p1, p2, p3 = object(), object(), object()

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
            self._cache._enqueue_pending(ADDR_A, p1)
            self._cache._enqueue_pending(ADDR_A, p2)
            self._cache._enqueue_pending(ADDR_A, p3)
            self._cache._add_entry(ADDR_A, MAC_A)

        self.assertEqual(
            self._flush_calls,
            [(p1, MAC_A), (p2, MAC_A), (p3, MAC_A)],
            msg="All queued packets must flush in FIFO order on resolution.",
        )

    def test__lib__neighbor__pending_queue_bounded_drops_oldest(self) -> None:
        """
        Ensure the pending queue is bounded by the
        'neighbor.unres_qlen' sysctl and, on overflow, drops
        the oldest packet (keeping the newest within the
        bound) — matching the Linux unresolved-queue policy.

        Reference: RFC 1122 §2.3.2.2 (save unresolved packets, transmit on resolution).
        """

        p1, p2, p3, p4, p5 = object(), object(), object(), object(), object()

        with sysctl_module.override("neighbor.default.unres_qlen", 3):
            with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
                self._cache._find_entry(ADDR_A)
                for pkt in (p1, p2, p3, p4, p5):
                    self._cache._enqueue_pending(ADDR_A, pkt)
                self._cache._add_entry(ADDR_A, MAC_A)

        self.assertEqual(
            self._flush_calls,
            [(p3, MAC_A), (p4, MAC_A), (p5, MAC_A)],
            msg="Overflow must drop the oldest packets and keep the newest within unres_qlen.",
        )


class TestNeighborCacheAgingBoundaries(_NeighborCacheFixture):
    """
    Exact-threshold coverage of the NUD aging transitions. The
    existing transition tests exercise the inclusive '>='
    timers / counters only strictly above (age 31 vs the 30 s
    timer, probe_count well over the limit), so the
    '>=' -> '>' relaxation survives. These pin the transition
    at the exact boundary value.
    """

    def test__lib__neighbor__reachable_to_stale_at_exact_reachable_time(self) -> None:
        """
        Ensure a REACHABLE entry transitions to STALE at an age
        of exactly REACHABLE_TIME — the inclusive boundary, not
        only strictly past it.

        Reference: RFC 4861 §7.3.3 (REACHABLE_TIME inclusive boundary).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        # REACHABLE_TIME default is 30 s; age is EXACTLY 30 here.
        self._run_loop_once(now=1030.0)

        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.STALE,
            msg="At an age of exactly REACHABLE_TIME the entry must already be STALE.",
        )

    def test__lib__neighbor__incomplete_to_failed_at_exact_max_multicast_solicit(self) -> None:
        """
        Ensure an INCOMPLETE entry transitions to FAILED once its
        probe_count reaches exactly MAX_MULTICAST_SOLICIT.

        Reference: RFC 4861 §7.3.3 (give up after MAX_MULTICAST_SOLICIT).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
        entry = self._cache._entries[ADDR_A]
        object.__setattr__(entry, "probe_count", 3)  # == MAX_MULTICAST_SOLICIT default

        self._run_loop_once(now=1000.5)

        self.assertIs(
            entry.state,
            NudState.FAILED,
            msg="At probe_count == MAX_MULTICAST_SOLICIT the INCOMPLETE entry must FAIL.",
        )

    def test__lib__neighbor__incomplete_below_max_solicit_not_failed(self) -> None:
        """
        Ensure an INCOMPLETE entry whose probe_count is one below
        MAX_MULTICAST_SOLICIT is NOT failed (pins the boundary
        against an off-by-one relaxation).

        Reference: RFC 4861 §7.3.3 (do not give up before the limit).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
        entry = self._cache._entries[ADDR_A]
        object.__setattr__(entry, "probe_count", 2)  # < MAX_MULTICAST_SOLICIT

        # Age 0.5 s < RETRANS_TIMER so no re-solicit either; state holds.
        self._run_loop_once(now=1000.5)

        self.assertIs(
            entry.state,
            NudState.INCOMPLETE,
            msg="Below MAX_MULTICAST_SOLICIT the INCOMPLETE entry must NOT fail.",
        )

    def test__lib__neighbor__probe_to_failed_at_exact_max_unicast_solicit(self) -> None:
        """
        Ensure a PROBE entry transitions to FAILED once its
        probe_count reaches exactly MAX_UNICAST_SOLICIT.

        Reference: RFC 4861 §7.3.3 (give up after MAX_UNICAST_SOLICIT).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        entry = self._cache._entries[ADDR_A]
        object.__setattr__(entry, "state", NudState.PROBE)
        object.__setattr__(entry, "probe_count", 3)  # == MAX_UNICAST_SOLICIT default
        object.__setattr__(entry, "state_changed_at", 1000.0)

        self._run_loop_once(now=1000.5)

        self.assertIs(
            entry.state,
            NudState.FAILED,
            msg="At probe_count == MAX_UNICAST_SOLICIT the PROBE entry must FAIL.",
        )

    def test__lib__neighbor__delay_to_probe_at_exact_delay_first_probe_time(self) -> None:
        """
        Ensure a DELAY entry transitions to PROBE at an age of
        exactly DELAY_FIRST_PROBE_TIME.

        Reference: RFC 4861 §7.3.3 (DELAY_FIRST_PROBE_TIME inclusive boundary).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        entry = self._cache._entries[ADDR_A]
        object.__setattr__(entry, "state", NudState.DELAY)
        object.__setattr__(entry, "state_changed_at", 1000.0)

        # DELAY_FIRST_PROBE_TIME default is 5 s; age is EXACTLY 5.
        self._run_loop_once(now=1005.0)

        self.assertIs(
            entry.state,
            NudState.PROBE,
            msg="At an age of exactly DELAY_FIRST_PROBE_TIME the DELAY entry must enter PROBE.",
        )

    def test__lib__neighbor__incomplete_resolicits_at_exact_retrans_timer(self) -> None:
        """
        Ensure an INCOMPLETE entry below the solicit limit
        re-solicits (incrementing probe_count) at an age of
        exactly RETRANS_TIMER.

        Reference: RFC 4861 §7.2.2 (RETRANS_TIMER multicast re-solicit cadence).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._find_entry(ADDR_A)
        entry = self._cache._entries[ADDR_A]
        object.__setattr__(entry, "probe_count", 1)
        object.__setattr__(entry, "state_changed_at", 1000.0)
        self._solicit_calls.clear()

        # RETRANS_TIMER default is 1 s; age is EXACTLY 1.
        self._run_loop_once(now=1001.0)

        self.assertEqual(
            entry.probe_count,
            2,
            msg="At an age of exactly RETRANS_TIMER the INCOMPLETE entry must re-solicit (probe_count 1 -> 2).",
        )
        self.assertEqual(
            len(self._solicit_calls),
            1,
            msg="The exact-RETRANS_TIMER re-solicit must fire one solicit.",
        )

    def test__lib__neighbor__probe_resolicits_at_exact_retrans_timer(self) -> None:
        """
        Ensure a PROBE entry below the unicast-solicit limit
        re-solicits (incrementing probe_count) at an age of
        exactly RETRANS_TIMER.

        Reference: RFC 4861 §7.3.3 (RETRANS_TIMER unicast re-solicit cadence).
        """

        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)
        entry = self._cache._entries[ADDR_A]
        object.__setattr__(entry, "state", NudState.PROBE)
        object.__setattr__(entry, "probe_count", 1)
        object.__setattr__(entry, "state_changed_at", 1000.0)

        self._run_loop_once(now=1001.0)

        self.assertEqual(
            entry.probe_count,
            2,
            msg="At an age of exactly RETRANS_TIMER the PROBE entry must re-solicit (probe_count 1 -> 2).",
        )


class TestNeighborCacheReachableTimeOverride(_NeighborCacheFixture):
    """
    The RA-driven Reachable Time override
    ('set_reachable_time_override_ms') — millisecond-to-second
    conversion and its effect on the REACHABLE -> STALE timer.
    """

    def test__lib__neighbor__reachable_time_override_converts_ms_to_seconds(self) -> None:
        """
        Ensure the override stores the value converted from
        milliseconds to seconds, and that None clears it.

        Reference: RFC 4861 §6.3.4 (RA Reachable Time in milliseconds).
        """

        self._cache.set_reachable_time_override_ms(30000)
        self.assertEqual(
            self._cache._reachable_time_override_s,
            30.0,
            msg="A 30000 ms override must be stored as 30.0 s.",
        )

        self._cache.set_reachable_time_override_ms(None)
        self.assertIsNone(
            self._cache._reachable_time_override_s,
            msg="Passing None must clear the override.",
        )

    def test__lib__neighbor__reachable_time_override_drives_stale_timer(self) -> None:
        """
        Ensure the override (not the sysctl default) governs the
        REACHABLE -> STALE transition: a 10 s override ages a
        REACHABLE entry to STALE at age 10, where the 30 s
        default would not.

        Reference: RFC 4861 §6.3.4 (RA Reachable Time overrides the default).
        """

        self._cache.set_reachable_time_override_ms(10000)  # 10 s
        with patch("pytcp.lib.neighbor.time.monotonic", return_value=1000.0):
            self._cache._add_entry(ADDR_A, MAC_A)

        # Age 9 s < 10 s override: still REACHABLE.
        self._run_loop_once(now=1009.0)
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.REACHABLE,
            msg="Below the 10 s override the entry must remain REACHABLE.",
        )

        # Age 10 s == override: STALE (the 30 s default would not fire here).
        self._run_loop_once(now=1010.0)
        self.assertIs(
            self._cache._entries[ADDR_A].state,
            NudState.STALE,
            msg="At the 10 s override boundary the entry must transition to STALE.",
        )
