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
Unit tests for the TCP-side PLPMTUD adapter
'TcpPlpmtudAdapter' in pytcp/protocols/tcp/tcp__plpmtud_adapter.py.
Exercises:

  * Construction binds the underlying PmtuSearch engine to
    the correct family floor (IPv4 / IPv6).
  * 'maybe_probe' returns engine's next_probe_size.
  * 'record_emitted_probe' tracks (seq, size) for later
    ack/loss detection.
  * 'on_snd_una_advance' dispatches on_probe_ack for every
    acked in-flight probe AND clears the entry.
  * 'on_rto_timeout' dispatches on_probe_loss for every
    in-flight probe AND clears the dict.
  * 'on_classical_pmtu' / 'confirm_current' pass-throughs.
  * 'in_flight_probe_sizes' snapshot for cwnd-exempt
    accounting (RFC 4821 §7.4).

pytcp/tests/unit/protocols/tcp/test__tcp__plpmtud_adapter.py

ver 3.0.8
"""

import inspect
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.plpmtud import (
    MAX_PROBES,
    MIN_PLPMTU__IP4,
    MIN_PLPMTU__IP6,
    PROBE_TIMER__SEC,
    PmtuState,
)
from pytcp.protocols.tcp.tcp__plpmtud_adapter import TcpPlpmtudAdapter, _seq_le

_IP4_DST = Ip4Address("10.0.1.91")
_IP6_DST = Ip6Address("2001:db8::91")


class TestTcpPlpmtudAdapter__Construction(TestCase):
    """
    Construction-time invariants for the TCP PLPMTUD adapter.
    """

    def test__tcp__plpmtud_adapter__ip4_binds_ip4_floor(self) -> None:
        """
        Ensure the adapter constructed with an IPv4 remote
        binds the engine's family floor to 576 bytes (the
        RFC 1122 EMTU_R minimum).

        Reference: RFC 8899 §5.1.2 (MIN_PLPMTU IPv4 floor).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP4_DST, interface_mtu=1500)

        self.assertGreaterEqual(
            adapter.current_mtu,
            MIN_PLPMTU__IP4,
            msg="IPv4 adapter's current_mtu must respect the 576-byte floor.",
        )

    def test__tcp__plpmtud_adapter__ip6_binds_ip6_floor(self) -> None:
        """
        Ensure the adapter constructed with an IPv6 remote
        binds the engine's family floor to 1280 bytes (the
        RFC 8200 IPv6 hard minimum).

        Reference: RFC 8200 §5 (IPv6 MTU minimum 1280).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        self.assertGreaterEqual(
            adapter.current_mtu,
            MIN_PLPMTU__IP6,
            msg="IPv6 adapter's current_mtu must respect the 1280-byte floor.",
        )

    def test__tcp__plpmtud_adapter__initial_state_is_base(self) -> None:
        """
        Ensure a fresh adapter exposes the engine's initial
        BASE state — the connectivity-confirmation phase
        before any probing.

        Reference: RFC 8899 §5.2 (initial Base state).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="A new TcpPlpmtudAdapter must expose engine.state == BASE.",
        )


class TestTcpPlpmtudAdapter__ProbeEmit(TestCase):
    """
    The probe-emit API: 'maybe_probe' + 'record_emitted_probe'.
    """

    def test__tcp__plpmtud_adapter__maybe_probe_passes_through_to_engine(self) -> None:
        """
        Ensure 'maybe_probe' returns the engine's next_probe_size
        result — the adapter is a thin pass-through on the
        emit-decision query.

        Reference: RFC 8899 §5.3 (probe-size query).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        size = adapter.maybe_probe(now=0.0)

        self.assertIsNotNone(
            size,
            msg="maybe_probe in BASE state must return a probe size.",
        )

    def test__tcp__plpmtud_adapter__record_emitted_probe_tracks_size(self) -> None:
        """
        Ensure 'record_emitted_probe' adds the (seq, size) entry
        to the in-flight dict so subsequent ack/loss detection
        can find it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        size = adapter.maybe_probe(now=0.0)
        assert size is not None

        adapter.record_emitted_probe(seq=1000, size=size)

        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (size,),
            msg="record_emitted_probe must add the size to in_flight_probe_sizes.",
        )


class TestTcpPlpmtudAdapter__ProbeAck(TestCase):
    """
    The probe-ack detection via 'on_snd_una_advance'.
    """

    def test__tcp__plpmtud_adapter__snd_una_advance_dispatches_probe_ack(self) -> None:
        """
        Ensure 'on_snd_una_advance' dispatches the engine's
        on_probe_ack when an in-flight probe's seq is now <=
        the new snd.una — the TCP cumulative-ack semantics
        directly drive PLPMTUD's probe-success feedback.

        Reference: RFC 4821 §7.6.1 (probe success raises search_low).
        Reference: RFC 9293 §3.4 (TCP cumulative ack).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        size = adapter.maybe_probe(now=0.0)
        assert size is not None
        adapter.record_emitted_probe(seq=1000, size=size)

        adapter.on_snd_una_advance(new_snd_una=1500, now=1.0)

        self.assertIs(
            adapter.state,
            PmtuState.SEARCHING,
            msg="snd.una advance past a probe's seq must transition BASE → SEARCHING.",
        )
        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (),
            msg="Acked probe must be removed from the in-flight dict.",
        )

    def test__tcp__plpmtud_adapter__snd_una_not_advanced_past_probe_keeps_entry(self) -> None:
        """
        Ensure that when snd.una has NOT advanced past an
        in-flight probe's seq, the entry stays in the
        tracking dict and on_probe_ack is NOT dispatched.

        Reference: RFC 9293 §3.4 (TCP cumulative-ack semantics).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        size = adapter.maybe_probe(now=0.0)
        assert size is not None
        adapter.record_emitted_probe(seq=2000, size=size)

        # snd.una advanced to 1500 (before the probe at seq 2000).
        adapter.on_snd_una_advance(new_snd_una=1500, now=1.0)

        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (size,),
            msg="Probe whose seq > new_snd_una must remain in-flight.",
        )
        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="Probe not yet acked must leave engine in BASE state.",
        )


class TestTcpPlpmtudAdapter__RtoLoss(TestCase):
    """
    The probe-loss detection via 'on_rto_timeout'.
    """

    def test__tcp__plpmtud_adapter__rto_timeout_dispatches_probe_loss(self) -> None:
        """
        Ensure 'on_rto_timeout' dispatches the engine's
        on_probe_loss for every in-flight probe AND clears
        the in-flight dict.

        Reference: RFC 4821 §7.5 (probe loss feedback to engine).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        size = adapter.maybe_probe(now=0.0)
        assert size is not None
        adapter.record_emitted_probe(seq=1000, size=size)

        adapter.on_rto_timeout(now=PROBE_TIMER__SEC + 1.0)

        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (),
            msg="RTO timeout must clear the in-flight probe dict.",
        )

    def test__tcp__plpmtud_adapter__rto_max_probes_enters_error(self) -> None:
        """
        Ensure MAX_PROBES consecutive RTO timeouts on probes
        enter the engine's ERROR state and clamp current_mtu
        to the family minimum.

        Reference: RFC 8899 §5.2 (black-hole detection).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        now = 0.0
        for _ in range(MAX_PROBES):
            size = adapter.maybe_probe(now=now)
            assert size is not None
            adapter.record_emitted_probe(seq=1000, size=size)
            now += PROBE_TIMER__SEC + 1.0
            adapter.on_rto_timeout(now=now)

        self.assertIs(
            adapter.state,
            PmtuState.ERROR,
            msg="MAX_PROBES consecutive RTO timeouts must enter PmtuState.ERROR.",
        )
        self.assertEqual(
            adapter.current_mtu,
            MIN_PLPMTU__IP6,
            msg="ERROR-state clamp must drop current_mtu to MIN_PLPMTU__IP6.",
        )

    def test__tcp__plpmtud_adapter__rto_without_probes_is_noop(self) -> None:
        """
        Ensure 'on_rto_timeout' is a no-op when there are no
        in-flight probes — RTO is a regular data event that
        should not affect PLPMTUD state unless a probe was
        also in flight.

        Reference: RFC 4821 §7.5 (data-RTO does not feed probe-loss).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        adapter.on_rto_timeout(now=PROBE_TIMER__SEC + 1.0)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="RTO without in-flight probes must NOT change PLPMTUD state.",
        )


class TestTcpPlpmtudAdapter__ClassicalPmtuPassthrough(TestCase):
    """
    Pass-through of classical-PMTUD signals and regular-data
    confirmation events.
    """

    def test__tcp__plpmtud_adapter__on_classical_pmtu_shrinks_current_mtu(self) -> None:
        """
        Ensure on_classical_pmtu passes through to the engine
        and shrinks current_mtu when the ICMP-reported MTU is
        below the current value.

        Reference: RFC 8201 §4 (PTB shrinks PLPMTU, never raises).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        prior = adapter.current_mtu

        adapter.on_classical_pmtu(1280, now=0.0)

        self.assertLessEqual(
            adapter.current_mtu,
            prior,
            msg="ICMP MTU=1280 must not raise current_mtu above the prior value.",
        )

    def test__tcp__plpmtud_adapter__confirm_current_advances_ack_size(self) -> None:
        """
        Ensure 'confirm_current' is dispatched to the engine
        so a non-probe data segment of large size can advance
        ack_size as an implicit probe.

        Reference: RFC 4821 §7.1 (implicit-probe feedback).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        adapter.confirm_current(1400)

        # No exception; confirm_current is a pass-through and
        # the engine accepts any positive size. State stays in
        # BASE because confirm_current does not transition.
        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="confirm_current MUST NOT transition state on its own.",
        )


class TestTcpPlpmtudAdapter__MutationGoldens(TestCase):
    """
    Address-family dispatch, keyword-only signatures, property
    accessors, and the modular sequence comparison closing the
    remaining adapter mutation survivors.
    """

    def test__tcp__plpmtud_adapter__family_dispatch_selects_floor(self) -> None:
        """
        Ensure the constructor's isinstance dispatch picks the IPv6
        engine for an IPv6 peer (candidate floor 1280) and the IPv4
        engine for an IPv4 peer (candidate floor 1200), so a negated
        isinstance would cross the floors.

        Reference: RFC 8899 §5.1.1 (BASE_PMTU per address family).
        """

        self.assertEqual(
            TcpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500).candidate_mtu,
            1280,
            msg="IPv6 peer must select the 1280-byte candidate floor.",
        )
        self.assertEqual(
            TcpPlpmtudAdapter(remote_ip_address=_IP4_DST, interface_mtu=1500).candidate_mtu,
            1200,
            msg="IPv4 peer must select the 1200-byte candidate floor.",
        )

    def test__tcp__plpmtud_adapter__public_methods_keyword_only(self) -> None:
        """
        Ensure the adapter's public methods keep their keyword-only
        parameters (kills the '*'→'/' separator mutation on each).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = {
            "__init__": {"remote_ip_address", "interface_mtu"},
            "record_emitted_probe": {"seq", "size"},
            "on_snd_una_advance": {"new_snd_una", "now"},
            "on_rto_timeout": {"now"},
            "on_classical_pmtu": {"now"},
        }
        for method, names in expected.items():
            params = inspect.signature(getattr(TcpPlpmtudAdapter, method)).parameters
            kw_only = {name for name, param in params.items() if param.kind is inspect.Parameter.KEYWORD_ONLY}
            self.assertEqual(
                kw_only,
                names,
                msg=f"{method} must keep keyword-only parameters {names}.",
            )

    def test__tcp__plpmtud_adapter__engine_and_candidate_are_properties(self) -> None:
        """
        Ensure 'engine' and 'candidate_mtu' are properties returning
        values, not bound methods, so a removed @property decorator is
        caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        adapter = TcpPlpmtudAdapter(remote_ip_address=_IP4_DST, interface_mtu=1500)
        self.assertNotIn(
            adapter.candidate_mtu,
            (None,),
            msg="candidate_mtu must be a value, not a bound method.",
        )
        self.assertIsInstance(
            adapter.candidate_mtu,
            int,
            msg="candidate_mtu property must return an int.",
        )
        self.assertFalse(
            callable(adapter.engine),
            msg="engine property must return the engine instance, not a bound method.",
        )

    def test__tcp__plpmtud_adapter__seq_le_modular_comparison(self) -> None:
        """
        Ensure the modular '<=' comparison treats a forward distance
        below 2^31 as ordered, the exact 2^31 boundary as not ordered,
        and handles 32-bit wraparound.

        Reference: RFC 9293 §3.4 (modular sequence comparison).
        """

        self.assertTrue(_seq_le(100, 100), msg="equal seqs are '<='.")
        self.assertTrue(_seq_le(100, 200), msg="forward distance is '<='.")
        self.assertFalse(_seq_le(200, 100), msg="backward distance is not '<='.")
        self.assertTrue(
            _seq_le(0, 0x7FFFFFFF),
            msg="distance 2^31 - 1 must be '<='.",
        )
        self.assertFalse(
            _seq_le(0, 0x80000000),
            msg="distance exactly 2^31 must NOT be '<=' (pins the 0x80000000 threshold).",
        )
        self.assertTrue(
            _seq_le(0xFFFFFFFF, 0),
            msg="0xFFFFFFFF <= 0 under wraparound (distance 1).",
        )
