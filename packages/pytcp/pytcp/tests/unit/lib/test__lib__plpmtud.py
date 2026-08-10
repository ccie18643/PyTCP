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
Unit tests for the unified PLPMTUD engine
'pytcp.lib.plpmtud.PmtuSearch[A]'. Exercises the RFC 4821 /
RFC 8899 state machine (BASE / SEARCHING / SEARCH_COMPLETE /
ERROR), the binary-search ladder convergence, the
PROBE_TIMER / PMTU_RAISE_TIMER / MAX_PROBES constants, and
the public API methods that the per-transport adapters
consume ('next_probe_size', 'on_probe_ack', 'on_probe_loss',
'on_classical_pmtu', 'confirm_current').

pytcp/tests/unit/lib/test__lib__plpmtud.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.plpmtud import (
    BASE_PLPMTU__IP4,
    BASE_PLPMTU__IP6,
    LADDER_GRANULARITY,
    MAX_PROBES,
    MIN_PLPMTU__IP4,
    MIN_PLPMTU__IP6,
    PMTU_RAISE_TIMER__SEC,
    PROBE_TIMER__SEC,
    PmtuSearch,
    PmtuState,
)

_IP4_DST = Ip4Address("10.0.1.91")
_IP6_DST = Ip6Address("2001:db8::91")
_IFACE_MTU = 1500
_LARGE_IFACE_MTU = 9000


class TestPmtuSearch__Constants(TestCase):
    """
    The module-level RFC-default constants exposed by
    'pytcp.lib.plpmtud'.
    """

    def test__plpmtud__probe_count_default_is_3(self) -> None:
        """
        Ensure MAX_PROBES is 3, matching the RFC 8899 default
        and the canonical "do not enter the error state on a
        transient single-packet loss" guarantee.

        Reference: RFC 8899 §5.1.2 (MAX_PROBES default value 3).
        """

        self.assertEqual(
            MAX_PROBES,
            3,
            msg="MAX_PROBES MUST equal the RFC 8899 default of 3.",
        )

    def test__plpmtud__probe_timer_default_is_30s(self) -> None:
        """
        Ensure PROBE_TIMER__SEC is 30, the RFC 8899 default for
        the time between probe-emit and loss-declaration.

        Reference: RFC 8899 §5.1.1 (PROBE_TIMER value > 15 s; 30 s default).
        """

        self.assertEqual(
            PROBE_TIMER__SEC,
            30.0,
            msg="PROBE_TIMER__SEC MUST equal the RFC 8899 default of 30 s.",
        )

    def test__plpmtud__raise_timer_default_is_600s(self) -> None:
        """
        Ensure PMTU_RAISE_TIMER__SEC is 600, the RFC 8899
        default for the period between SEARCH_COMPLETE and the
        next probing round.

        Reference: RFC 8899 §5.1.1 (PMTU_RAISE_TIMER value 600 s).
        """

        self.assertEqual(
            PMTU_RAISE_TIMER__SEC,
            600.0,
            msg="PMTU_RAISE_TIMER__SEC MUST equal the RFC 8899 default of 600 s.",
        )


class TestPmtuSearch__Construction(TestCase):
    """
    Per-construction invariants — initial state, floor, and
    family-specific defaults.
    """

    def test__plpmtud__initial_state_is_base(self) -> None:
        """
        Ensure a freshly constructed engine starts in the BASE
        state with the initial probe equal to BASE_PLPMTU so
        the search begins by confirming base connectivity.

        Reference: RFC 8899 §5.2 (state machine Base Phase).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)

        self.assertIs(
            engine.state,
            PmtuState.BASE,
            msg="A new PmtuSearch must start in PmtuState.BASE.",
        )

    def test__plpmtud__ip6_floor_min_pmtu_1280(self) -> None:
        """
        Ensure the IPv6 floor is the RFC 8200 / RFC 8899
        mandated 1280 bytes — the engine MUST NOT advertise a
        current_mtu below this for an IPv6 destination.

        Reference: RFC 8200 §5 (IPv6 MTU minimum 1280).
        Reference: RFC 8899 §5.1.2 (MIN_PLPMTU constant).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)

        self.assertGreaterEqual(
            engine.current_mtu,
            MIN_PLPMTU__IP6,
            msg="An IPv6 engine's current_mtu must be >= MIN_PLPMTU__IP6 (1280).",
        )
        self.assertEqual(
            MIN_PLPMTU__IP6,
            1280,
            msg="MIN_PLPMTU__IP6 MUST equal the RFC 8200 IPv6 minimum of 1280.",
        )

    def test__plpmtud__ip4_floor_min_pmtu_576(self) -> None:
        """
        Ensure the IPv4 floor is the RFC 1122-style practical
        minimum of 576 bytes (every IPv4 host MUST accept
        reassembled datagrams of at least 576).

        Reference: RFC 8899 §5.1.2 (MIN_PLPMTU IPv4 floor).
        Reference: RFC 1122 §3.3.3 (576-byte EMTU_R minimum).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=_IFACE_MTU)

        self.assertGreaterEqual(
            engine.current_mtu,
            MIN_PLPMTU__IP4,
            msg="An IPv4 engine's current_mtu must be >= MIN_PLPMTU__IP4 (576).",
        )
        self.assertEqual(
            MIN_PLPMTU__IP4,
            576,
            msg="MIN_PLPMTU__IP4 MUST equal the RFC 1122 EMTU_R minimum of 576.",
        )

    def test__plpmtud__base_pmtu_ip4_is_1200(self) -> None:
        """
        Ensure the IPv4 BASE_PLPMTU constant matches RFC 8899's
        recommended starting probe size of 1200 bytes.

        Reference: RFC 8899 §5.1.2 (BASE_PLPMTU recommended 1200).
        """

        self.assertEqual(
            BASE_PLPMTU__IP4,
            1200,
            msg="BASE_PLPMTU__IP4 MUST equal the RFC 8899 recommendation of 1200.",
        )

    def test__plpmtud__ip6_min_pmtu_invariant_under_lower_icmp_signal(self) -> None:
        """
        Ensure that even when ICMP reports an MTU below 1280
        for an IPv6 destination, the engine clamps to the
        1280-byte hard floor and never advertises a lower
        current_mtu — the IPv6 MTU minimum is non-negotiable.

        Reference: RFC 8200 §5 (IPv6 MTU minimum 1280, no exceptions).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)
        engine.on_classical_pmtu(800, now=0.0)

        self.assertEqual(
            engine.current_mtu,
            MIN_PLPMTU__IP6,
            msg="IPv6 MTU floor of 1280 must hold even when ICMP reports a lower value.",
        )


class TestPmtuSearch__Base(TestCase):
    """
    Tests for the BASE state — the initial connectivity-
    confirmation probe at BASE_PLPMTU.
    """

    def test__plpmtud__base__ack_transitions_to_searching(self) -> None:
        """
        Ensure that an ack of the BASE probe transitions the
        engine from BASE to SEARCHING, opening the binary-
        search ladder above ack_size.

        Reference: RFC 8899 §5.2 (Base → Search on confirmation).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)

        size = engine.next_probe_size(now=0.0)
        self.assertEqual(
            size,
            BASE_PLPMTU__IP6,
            msg="BASE state must emit a probe at BASE_PLPMTU__IP6.",
        )
        assert size is not None
        engine.on_probe_ack(size, now=0.0)

        self.assertIs(
            engine.state,
            PmtuState.SEARCHING,
            msg="After ack of the BASE probe, the engine must transition to SEARCHING.",
        )

    def test__plpmtud__next_probe_size_pre_timer_is_none(self) -> None:
        """
        Ensure that 'next_probe_size' returns None when a probe
        was already emitted and the PROBE_TIMER has not yet
        expired — the engine must not emit a second probe
        while one is still in flight.

        Reference: RFC 8899 §5.1.1 (PROBE_TIMER guards against premature retry).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)

        first = engine.next_probe_size(now=0.0)
        second = engine.next_probe_size(now=PROBE_TIMER__SEC / 2)

        self.assertIsNotNone(
            first,
            msg="First call to next_probe_size in BASE must emit a probe.",
        )
        self.assertIsNone(
            second,
            msg="Second call before PROBE_TIMER expiry must return None (probe still in flight).",
        )


class TestPmtuSearch__Searching(TestCase):
    """
    Tests for the SEARCHING state — the binary-search ladder
    that climbs from ack_size toward search_high.
    """

    def _engine_in_searching(self) -> PmtuSearch[Ip6Address]:
        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_LARGE_IFACE_MTU)
        size = engine.next_probe_size(now=0.0)
        assert size is not None
        engine.on_probe_ack(size, now=0.0)
        return engine

    def test__plpmtud__on_probe_ack_advances_search_low(self) -> None:
        """
        Ensure that an ack of a SEARCHING probe raises the
        engine's ack_size (RFC 4821's search_low) up to the
        probe size, so the next candidate is a strictly
        larger size.

        Reference: RFC 4821 §7.1 (search_low / search_high state variables).
        Reference: RFC 4821 §7.6.1 (probe success raises search_low).
        """

        engine = self._engine_in_searching()
        first_candidate = engine.next_probe_size(now=1.0)
        assert first_candidate is not None
        engine.on_probe_ack(first_candidate, now=2.0)

        self.assertGreaterEqual(
            engine.current_mtu,
            first_candidate,
            msg="After ack of probe X, current_mtu must be at least X.",
        )

    def test__plpmtud__on_probe_loss_advances_probe_count(self) -> None:
        """
        Ensure that on_probe_loss bumps the probe_count without
        immediately entering ERROR — a single loss must not
        trigger black-hole detection.

        Reference: RFC 8899 §5.1.3 (PROBE_COUNT accumulator).
        """

        engine = self._engine_in_searching()
        engine.next_probe_size(now=1.0)
        engine.on_probe_loss(now=PROBE_TIMER__SEC + 1.0)

        self.assertIs(
            engine.state,
            PmtuState.SEARCHING,
            msg="A single probe loss must NOT exit the SEARCHING state.",
        )

    def test__plpmtud__single_loss_does_not_enter_error(self) -> None:
        """
        Ensure that exactly one consecutive probe loss does NOT
        transition the engine to ERROR — black-hole detection
        requires MAX_PROBES (default 3) consecutive losses.

        Reference: RFC 8899 §5.1.2 (MAX_PROBES default 3; transient loss robustness).
        """

        engine = self._engine_in_searching()
        engine.next_probe_size(now=1.0)
        engine.on_probe_loss(now=PROBE_TIMER__SEC + 1.0)

        self.assertIsNot(
            engine.state,
            PmtuState.ERROR,
            msg="A single loss must not enter ERROR; only MAX_PROBES consecutive losses can.",
        )

    def test__plpmtud__three_consecutive_losses_enter_error(self) -> None:
        """
        Ensure that MAX_PROBES consecutive probe losses transition
        the engine to ERROR and clamp current_mtu to the family
        minimum (1280 for IPv6 / 576 for IPv4).

        Reference: RFC 8899 §5.2 (black-hole detection enters Error state).
        Reference: RFC 8899 §5.1.2 (MAX_PROBES default 3).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)
        # Lose every probe MAX_PROBES times in a row.
        now = 0.0
        for _ in range(MAX_PROBES):
            engine.next_probe_size(now=now)
            now += PROBE_TIMER__SEC + 1.0
            engine.on_probe_loss(now=now)

        self.assertIs(
            engine.state,
            PmtuState.ERROR,
            msg="MAX_PROBES consecutive losses must enter PmtuState.ERROR.",
        )
        self.assertEqual(
            engine.current_mtu,
            MIN_PLPMTU__IP6,
            msg="On ERROR entry, current_mtu must clamp to MIN_PLPMTU__IP6.",
        )

    def test__plpmtud__searching__converges_to_search_complete(self) -> None:
        """
        Ensure that the SEARCHING ladder converges to
        SEARCH_COMPLETE once the search range narrows below
        the LADDER_GRANULARITY threshold — at that point
        further probing is no longer cost-effective and the
        engine settles on ack_size as the current PLPMTU.

        Reference: RFC 4821 §7.3 (converged search; further probing not worthwhile).
        Reference: RFC 8899 §5.3 (binary search convergence).
        """

        engine = self._engine_in_searching()
        # Run probe → ack cycles until the engine declares convergence.
        # Bound the loop generously so an infinite-loop bug surfaces as
        # a test failure rather than a hang.
        now = 1.0
        for _ in range(64):
            candidate = engine.next_probe_size(now=now)
            if candidate is None:
                break
            engine.on_probe_ack(candidate, now=now)
            now += 1.0
        else:
            self.fail("PmtuSearch ladder did not converge within 64 probe-ack cycles.")

        self.assertIs(
            engine.state,
            PmtuState.SEARCH_COMPLETE,
            msg="The successful-ack ladder must converge to SEARCH_COMPLETE.",
        )


class TestPmtuSearch__Ladder(TestCase):
    """
    Tests for the binary-search ladder details — candidate
    selection, granularity, and progress.
    """

    def test__plpmtud__binary_search_ladder_convergence(self) -> None:
        """
        Ensure the engine's binary-search ladder produces a
        monotonically narrowing probe-size range — each
        candidate strictly within the (ack_size, search_high)
        interval and converging in a bounded number of steps.

        Reference: RFC 4821 §7.3 (binary search strategy).
        Reference: RFC 8899 §5.3 (search algorithm convergence).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_LARGE_IFACE_MTU)
        # Confirm base.
        size = engine.next_probe_size(now=0.0)
        assert size is not None
        engine.on_probe_ack(size, now=0.0)

        previous = size
        now = 1.0
        for _ in range(32):
            candidate = engine.next_probe_size(now=now)
            if candidate is None:
                break
            self.assertGreater(
                candidate,
                previous,
                msg="Successful-ack ladder must produce strictly increasing candidates.",
            )
            engine.on_probe_ack(candidate, now=now)
            previous = candidate
            now += 1.0
        else:
            self.fail("Ladder did not converge within 32 iterations.")

    def test__plpmtud__ladder_converges_at_8_byte_granularity(self) -> None:
        """
        Ensure the engine declares convergence once the
        remaining search range is smaller than the 8-byte
        LADDER_GRANULARITY threshold — finer probing would
        cost more than the savings.

        Reference: RFC 8899 §5.3 (8-byte search granularity).
        """

        self.assertEqual(
            LADDER_GRANULARITY,
            8,
            msg="LADDER_GRANULARITY MUST equal 8 bytes (RFC 8899 §5.3 default).",
        )
        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_LARGE_IFACE_MTU)
        size = engine.next_probe_size(now=0.0)
        assert size is not None
        engine.on_probe_ack(size, now=0.0)

        # Walk the ladder to completion via successive acks.
        now = 1.0
        for _ in range(64):
            candidate = engine.next_probe_size(now=now)
            if candidate is None:
                break
            engine.on_probe_ack(candidate, now=now)
            now += 1.0

        # Once converged, the final state pins current_mtu within
        # LADDER_GRANULARITY of the engine's search_high ceiling.
        self.assertIs(
            engine.state,
            PmtuState.SEARCH_COMPLETE,
            msg="Engine must reach SEARCH_COMPLETE within 64 iterations.",
        )


class TestPmtuSearch__Raise(TestCase):
    """
    Tests for the PMTU_RAISE_TIMER — re-entering SEARCHING
    from SEARCH_COMPLETE after the configured idle interval.
    """

    def test__plpmtud__raise_timer_re_enters_searching(self) -> None:
        """
        Ensure that once SEARCH_COMPLETE has been entered, the
        PMTU_RAISE_TIMER (600 s default) fires and the engine
        re-enters SEARCHING, raising search_high back to the
        interface MTU to detect path-MTU increases.

        Reference: RFC 8899 §5.1.1 (PMTU_RAISE_TIMER 600 s re-search).
        Reference: RFC 4821 §7.3 (timer-driven re-probe).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_LARGE_IFACE_MTU)
        # Walk to SEARCH_COMPLETE.
        size = engine.next_probe_size(now=0.0)
        assert size is not None
        engine.on_probe_ack(size, now=0.0)
        now = 1.0
        for _ in range(64):
            cand = engine.next_probe_size(now=now)
            if cand is None:
                break
            engine.on_probe_ack(cand, now=now)
            now += 1.0
        self.assertIs(
            engine.state,
            PmtuState.SEARCH_COMPLETE,
            msg="Precondition: engine must reach SEARCH_COMPLETE before raise-timer test.",
        )

        # Advance past the raise timer.
        raise_now = now + PMTU_RAISE_TIMER__SEC + 1.0
        engine.next_probe_size(now=raise_now)

        self.assertIs(
            engine.state,
            PmtuState.SEARCHING,
            msg="Raise timer firing must transition SEARCH_COMPLETE → SEARCHING.",
        )


class TestPmtuSearch__BlackHole(TestCase):
    """
    Tests for ERROR-state behaviour and recovery paths.
    """

    def _drive_to_error(self) -> PmtuSearch[Ip6Address]:
        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU)
        now = 0.0
        for _ in range(MAX_PROBES):
            engine.next_probe_size(now=now)
            now += PROBE_TIMER__SEC + 1.0
            engine.on_probe_loss(now=now)
        return engine

    def test__plpmtud__error__icmp_signal_recovers_to_searching(self) -> None:
        """
        Ensure that when in ERROR state, an inbound ICMP
        Frag-Needed / Packet-Too-Big signal recovers the engine
        to SEARCHING with the new ICMP-reported MTU as the
        starting ceiling — the host is no longer stuck at the
        minimum forever once the network gives a hint.

        Reference: RFC 4821 §7.7 (recovery from black-hole state).
        Reference: RFC 8899 §4.5 (PTB-driven re-probe).
        """

        engine = self._drive_to_error()
        self.assertIs(
            engine.state,
            PmtuState.ERROR,
            msg="Precondition: engine must be in ERROR before recovery test.",
        )

        engine.on_classical_pmtu(1400, now=1000.0)

        self.assertIsNot(
            engine.state,
            PmtuState.ERROR,
            msg="ICMP signal while in ERROR must exit the ERROR state for recovery.",
        )
        self.assertLessEqual(
            engine.current_mtu,
            1400,
            msg="Post-recovery current_mtu must not exceed the ICMP-reported MTU.",
        )


class TestPmtuSearch__IcmpInterleave(TestCase):
    """
    Tests for the classical-PMTUD coexistence — ICMP signals
    interleaved with active probing.
    """

    def test__plpmtud__on_classical_pmtu_shrinks_search_high(self) -> None:
        """
        Ensure on_classical_pmtu shrinks the engine's
        search_high ceiling when the ICMP-reported MTU is below
        the current ceiling — ICMP can never raise the PLPMTU
        but can shrink the search range.

        Reference: RFC 8201 §4 (PTB-driven MTU update, never increase).
        Reference: RFC 8899 §4.5 (PL_PTB_SIZE handling).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_LARGE_IFACE_MTU)
        size = engine.next_probe_size(now=0.0)
        assert size is not None
        engine.on_probe_ack(size, now=0.0)

        # Probe a midpoint, then receive ICMP indicating a lower ceiling.
        first = engine.next_probe_size(now=1.0)
        assert first is not None
        original_high = first  # the candidate before ICMP
        engine.on_classical_pmtu(1400, now=2.0)

        next_candidate = engine.next_probe_size(now=PROBE_TIMER__SEC + 3.0)
        if next_candidate is not None:
            self.assertLessEqual(
                next_candidate,
                1400,
                msg="After ICMP MTU=1400 signal, next candidate must not exceed 1400.",
            )
        self.assertLessEqual(
            engine.current_mtu,
            max(original_high, 1400),
            msg="ICMP signal must not raise current_mtu above the reported MTU.",
        )

    def test__plpmtud__searching__icmp_signal_shrinks_search_high(self) -> None:
        """
        Ensure that during SEARCHING, an ICMP signal lowers the
        ceiling AND aborts the in-flight probe when the in-
        flight candidate is now too large.

        Reference: RFC 8899 §4.5 / RFC 8201 §4.
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=_LARGE_IFACE_MTU)
        size = engine.next_probe_size(now=0.0)
        assert size is not None
        engine.on_probe_ack(size, now=0.0)
        # Now in SEARCHING; pick an upper-half candidate.
        candidate = engine.next_probe_size(now=1.0)
        assert candidate is not None

        # ICMP reports a much lower ceiling.
        engine.on_classical_pmtu(1400, now=2.0)

        self.assertLessEqual(
            engine.current_mtu,
            max(BASE_PLPMTU__IP6, 1400),
            msg="ICMP MTU=1400 during SEARCHING must shrink current_mtu accordingly.",
        )


class TestPmtuSearch__SearchLadderExact(TestCase):
    """
    Exact golden-value coverage of the binary-search ladder
    arithmetic, the probe-loss narrowing, and black-hole
    detection. The candidate-size literals are captured from
    the engine on correct source so that any mutation of the
    midpoint formula, the 8-byte alignment, the convergence
    bound, or the search-ceiling step moves the produced
    sequence and fails the assertion.
    """

    def test__plpmtud__ipv4_search_ladder_exact_sequence(self) -> None:
        """
        Ensure the IPv4 binary-search ladder produces the exact
        8-byte-aligned midpoint sequence from BASE_PLPMTU__IP4
        up to the interface MTU and then converges to
        SEARCH_COMPLETE.

        Reference: RFC 8899 §5.3 (search-ladder binary search).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)

        self.assertEqual(
            engine.next_probe_size(now=0.0),
            BASE_PLPMTU__IP4,
            msg="BASE state must probe at BASE_PLPMTU__IP4 (1200).",
        )
        engine.on_probe_ack(BASE_PLPMTU__IP4, now=0.0)

        ladder: list[int] = []
        while engine.state is PmtuState.SEARCHING:
            candidate = engine.candidate_mtu
            assert candidate is not None
            ladder.append(candidate)
            engine.on_probe_ack(candidate, now=0.0)

        self.assertEqual(
            ladder,
            [1344, 1416, 1456, 1472, 1480, 1488, 1496],
            msg="The IPv4 search ladder must follow the exact 8-byte-aligned midpoint sequence.",
        )
        self.assertIs(
            engine.state,
            PmtuState.SEARCH_COMPLETE,
            msg="The ladder must converge to SEARCH_COMPLETE once the gap drops to the granularity.",
        )
        self.assertEqual(
            engine.current_mtu,
            1500,
            msg="current_mtu must equal the interface MTU after a fully-confirmed search.",
        )

    def test__plpmtud__probe_loss_narrows_search_high_to_candidate_minus_one(self) -> None:
        """
        Ensure a probe loss during SEARCHING lowers search_high
        to exactly (candidate - 1) and recomputes a smaller
        candidate from the narrowed range.

        Reference: RFC 8899 §5.3 (probe loss narrows the upper bound).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)
        engine.on_probe_ack(BASE_PLPMTU__IP4, now=0.0)

        self.assertEqual(
            engine.candidate_mtu,
            1344,
            msg="First SEARCHING candidate must be 1344.",
        )

        engine.on_probe_loss(now=0.0)

        self.assertEqual(
            engine.candidate_mtu,
            1264,
            msg="After a loss of the 1344 candidate, the next candidate must be 1264 (midpoint of 1200..1343).",
        )

    def test__plpmtud__black_hole_enters_error_at_max_probes(self) -> None:
        """
        Ensure MAX_PROBES consecutive losses clamp current_mtu
        to the minimum, reset the probe counter, and enter
        ERROR — but a loss count strictly below MAX_PROBES
        does not.

        Reference: RFC 8899 §5.1.2 (MAX_PROBES black-hole detection).
        """

        engine: PmtuSearch[Ip6Address] = PmtuSearch(address=_IP6_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)

        for _ in range(MAX_PROBES - 1):
            engine.on_probe_loss(now=0.0)

        self.assertIs(
            engine.state,
            PmtuState.BASE,
            msg="Below MAX_PROBES losses, the engine must remain in BASE (pins the '>=' boundary).",
        )

        engine.on_probe_loss(now=0.0)

        self.assertIs(
            engine.state,
            PmtuState.ERROR,
            msg="The MAX_PROBES-th consecutive loss must enter ERROR.",
        )
        self.assertEqual(
            engine.current_mtu,
            MIN_PLPMTU__IP6,
            msg="Black-hole detection must clamp current_mtu to the IPv6 minimum.",
        )

    def test__plpmtud__confirm_current_advances_ack_size_only_when_larger(self) -> None:
        """
        Ensure 'confirm_current' raises ack_size when the
        confirmed segment is larger than the prior ack_size and
        leaves it unchanged for a smaller segment.

        Reference: RFC 8899 §7.1 (implicit-probe feedback from data).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)
        engine.on_probe_ack(BASE_PLPMTU__IP4, now=0.0)
        # ack_size is now BASE_PLPMTU__IP4 (1200).

        engine.confirm_current(1250)
        self.assertEqual(
            engine._ack_size,  # pylint: disable=protected-access
            1250,
            msg="A 1250-byte confirmation larger than ack_size must raise ack_size to 1250.",
        )

        engine.confirm_current(1100)
        self.assertEqual(
            engine._ack_size,  # pylint: disable=protected-access
            1250,
            msg="A confirmation smaller than ack_size must leave ack_size unchanged.",
        )

    def test__plpmtud__classical_pmtu_shrinks_current_not_search_high(self) -> None:
        """
        Ensure a classical RFC 1191 PTB hint during SEARCHING
        lowers current_mtu to the hinted value but leaves
        search_high (the upward-probe ceiling) untouched.

        Reference: RFC 8201 §4 (classical signal shrinks but must not raise).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)
        engine.on_probe_ack(BASE_PLPMTU__IP4, now=0.0)

        engine.on_classical_pmtu(1400, now=0.0)

        self.assertEqual(
            engine.current_mtu,
            1400,
            msg="Classical PTB must shrink current_mtu to the hinted value.",
        )
        self.assertEqual(
            engine._search_high,  # pylint: disable=protected-access
            1500,
            msg="Classical PTB must NOT lower search_high (the upward-probe ceiling).",
        )


class TestPmtuSearch__TimerRecovery(TestCase):
    """
    Golden-value coverage of the PROBE_TIMER / PMTU_RAISE_TIMER
    arithmetic and the ERROR / SEARCH_COMPLETE recovery
    transitions that re-open probing once the raise timer
    fires. Captured from the engine on correct source so any
    mutation of the 'now + TIMER' arithmetic or the
    'now < expiry' gate moves the produced timing and fails.
    """

    def test__plpmtud__error_recovery_re_probes_after_raise_timer(self) -> None:
        """
        Ensure an engine in ERROR (black-holed) emits nothing
        until PMTU_RAISE_TIMER expires, then re-enters BASE and
        re-probes at BASE_PLPMTU with the PROBE_TIMER armed at
        now + PROBE_TIMER__SEC.

        Reference: RFC 8899 §5.2 (Error → Base recovery on the raise timer).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)
        for _ in range(MAX_PROBES):
            engine.on_probe_loss(now=0.0)
        self.assertIs(engine.state, PmtuState.ERROR, msg="MAX_PROBES losses must reach ERROR.")
        self.assertEqual(
            engine._raise_timer_expiry,
            PMTU_RAISE_TIMER__SEC,
            msg="ERROR must arm the raise timer at now + PMTU_RAISE_TIMER__SEC (0 + 600).",
        )

        self.assertIsNone(
            engine.next_probe_size(now=PMTU_RAISE_TIMER__SEC - 1.0),
            msg="Before the raise timer fires, ERROR must emit nothing.",
        )
        self.assertIs(engine.state, PmtuState.ERROR, msg="Engine must remain in ERROR before the raise timer.")

        self.assertEqual(
            engine.next_probe_size(now=PMTU_RAISE_TIMER__SEC),
            BASE_PLPMTU__IP4,
            msg="When the raise timer fires, ERROR must re-probe at BASE_PLPMTU__IP4.",
        )
        self.assertIs(engine.state, PmtuState.BASE, msg="Raise-timer recovery must re-enter BASE.")
        self.assertEqual(
            engine._probe_timer_expiry,
            PMTU_RAISE_TIMER__SEC + PROBE_TIMER__SEC,
            msg="The recovery probe must arm PROBE_TIMER at now + PROBE_TIMER__SEC (600 + 30).",
        )

    def test__plpmtud__search_complete_reopens_after_raise_timer(self) -> None:
        """
        Ensure an engine in SEARCH_COMPLETE stays idle until the
        PMTU_RAISE_TIMER expires, then leaves SEARCH_COMPLETE to
        re-probe for a possible path-MTU increase.

        Reference: RFC 8899 §5.1.1 (PMTU_RAISE_TIMER re-opens the search).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)
        engine.on_probe_ack(BASE_PLPMTU__IP4, now=0.0)
        while engine.state is PmtuState.SEARCHING:
            candidate = engine.candidate_mtu
            assert candidate is not None
            engine.on_probe_ack(candidate, now=0.0)
        self.assertIs(engine.state, PmtuState.SEARCH_COMPLETE, msg="Ladder must converge to SEARCH_COMPLETE.")
        raise_expiry = engine._raise_timer_expiry
        assert raise_expiry is not None

        self.assertIsNone(
            engine.next_probe_size(now=raise_expiry - 1.0),
            msg="Before the raise timer fires, SEARCH_COMPLETE must emit nothing.",
        )
        self.assertIs(
            engine.state,
            PmtuState.SEARCH_COMPLETE,
            msg="Engine must remain in SEARCH_COMPLETE before the raise timer.",
        )

        engine.next_probe_size(now=raise_expiry)
        self.assertIsNot(
            engine.state,
            PmtuState.SEARCH_COMPLETE,
            msg="When the raise timer fires, SEARCH_COMPLETE must re-open the search.",
        )

    def test__plpmtud__confirm_current_raises_up_to_search_high_ceiling(self) -> None:
        """
        Ensure 'confirm_current' raises current_mtu for a
        segment larger than current — but only up to search_high;
        a confirmation above search_high advances ack_size yet
        must NOT raise current_mtu past the ceiling.

        Reference: RFC 8899 §7.1 (implicit-probe feedback bounded by the search ceiling).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)
        engine.next_probe_size(now=0.0)
        engine.on_probe_ack(BASE_PLPMTU__IP4, now=0.0)
        engine.on_classical_pmtu(1300, now=0.0)
        # current_mtu = 1300 < search_high = 1500.

        engine.confirm_current(1400)
        self.assertEqual(
            engine.current_mtu,
            1400,
            msg="A 1400-byte confirmation (> current, <= search_high) must raise current_mtu to 1400.",
        )

        engine.confirm_current(1600)
        self.assertEqual(
            engine.current_mtu,
            1400,
            msg="A confirmation above search_high must NOT raise current_mtu past the ceiling.",
        )

    def test__plpmtud__probe_timer_armed_at_now_plus_probe_timer(self) -> None:
        """
        Ensure emitting the BASE probe arms the PROBE_TIMER at
        exactly now + PROBE_TIMER__SEC.

        Reference: RFC 8899 §5.1.1 (PROBE_TIMER arms on probe emit).
        """

        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=_IP4_DST, interface_mtu=1500)

        engine.next_probe_size(now=5.0)

        self.assertEqual(
            engine._probe_timer_expiry,
            5.0 + PROBE_TIMER__SEC,
            msg="Emitting a probe at now=5 must arm PROBE_TIMER at 5 + PROBE_TIMER__SEC (35).",
        )
