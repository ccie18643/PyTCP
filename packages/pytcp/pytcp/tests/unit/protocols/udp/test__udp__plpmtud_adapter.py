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
Unit tests for the UDP-side PLPMTUD adapter
'UdpPlpmtudAdapter' in pytcp/protocols/udp/udp__plpmtud_adapter.py.
Exercises:

  * Construction binds the engine to correct family floor.
  * 'probe_pmtu' reserves a probe slot using either the
    engine's recommendation or the application's chosen size.
  * Single-outstanding-probe invariant — concurrent
    probe_pmtu calls return None.
  * 'ack_probe' dispatches engine.on_probe_ack and clears
    the in-flight slot.
  * 'timeout_probe' dispatches engine.on_probe_loss and
    clears the in-flight slot.
  * MAX_PROBES consecutive timeouts → ERROR + min clamp.
  * 'on_classical_pmtu' pass-through.

pytcp/tests/unit/protocols/udp/test__udp__plpmtud_adapter.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.plpmtud import (
    MAX_PROBES,
    MIN_PLPMTU__IP4,
    MIN_PLPMTU__IP6,
    PmtuState,
)
from pytcp.protocols.udp.udp__plpmtud_adapter import UdpPlpmtudAdapter

_IP4_DST = Ip4Address("10.0.1.91")
_IP6_DST = Ip6Address("2001:db8::91")


class TestUdpPlpmtudAdapter__Construction(TestCase):
    """
    Construction-time invariants for the UDP PLPMTUD adapter.
    """

    def test__udp__plpmtud_adapter__ip4_binds_ip4_floor(self) -> None:
        """
        Ensure the adapter constructed with an IPv4 remote
        binds the engine's family floor to 576 bytes.

        Reference: RFC 8899 §5.1.2 (MIN_PLPMTU IPv4 floor).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP4_DST, interface_mtu=1500)

        self.assertGreaterEqual(
            adapter.current_mtu,
            MIN_PLPMTU__IP4,
            msg="IPv4 adapter's current_mtu must respect the 576-byte floor.",
        )

    def test__udp__plpmtud_adapter__ip6_binds_ip6_floor(self) -> None:
        """
        Ensure the adapter constructed with an IPv6 remote
        binds the engine's family floor to 1280 bytes.

        Reference: RFC 8200 §5 (IPv6 MTU minimum 1280).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        self.assertGreaterEqual(
            adapter.current_mtu,
            MIN_PLPMTU__IP6,
            msg="IPv6 adapter's current_mtu must respect the 1280-byte floor.",
        )

    def test__udp__plpmtud_adapter__initial_in_flight_is_none(self) -> None:
        """
        Ensure a fresh adapter has no in-flight probe — the
        first probe_pmtu call should always succeed in
        reserving the slot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        self.assertIsNone(
            adapter.in_flight_size,
            msg="A new UdpPlpmtudAdapter must have no in-flight probe.",
        )


class TestUdpPlpmtudAdapter__Probe(TestCase):
    """
    The probe-emit API: 'probe_pmtu' + in-flight tracking.
    """

    def test__udp__plpmtud_adapter__probe_pmtu_uses_engine_recommendation(self) -> None:
        """
        Ensure 'probe_pmtu' without an explicit size uses the
        engine's 'next_probe_size' recommendation and reserves
        that size in the in-flight slot.

        Reference: RFC 8899 §6 (datagram transport probe-send API).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        size = adapter.probe_pmtu(now=0.0)

        self.assertIsNotNone(
            size,
            msg="probe_pmtu in BASE state must reserve an engine-recommended probe.",
        )
        self.assertEqual(
            adapter.in_flight_size,
            size,
            msg="Reserved probe size must be reflected in in_flight_size.",
        )

    def test__udp__plpmtud_adapter__probe_pmtu_accepts_caller_size(self) -> None:
        """
        Ensure 'probe_pmtu' with an explicit 'size' uses that
        size verbatim — the application may know its own
        probe size (e.g. QUIC's MTU probe size policy) rather
        than relying on the engine's binary-search choice.

        Reference: RFC 8899 §3 #5 (PL may select probe size).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        size = adapter.probe_pmtu(size=1450, now=0.0)

        self.assertEqual(
            size,
            1450,
            msg="probe_pmtu(size=N) must return N verbatim.",
        )
        self.assertEqual(
            adapter.in_flight_size,
            1450,
            msg="in_flight_size must reflect the caller's chosen size.",
        )

    def test__udp__plpmtud_adapter__probe_pmtu_rejects_concurrent_probe(self) -> None:
        """
        Ensure 'probe_pmtu' returns None when an outstanding
        probe is already in flight — the single-outstanding
        invariant guarantees the application's app-layer ACK
        unambiguously maps to one probe.

        Reference: RFC 8899 §6 (probe loss recovery requires unambiguous ACK).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        first = adapter.probe_pmtu(now=0.0)
        assert first is not None

        second = adapter.probe_pmtu(now=1.0)

        self.assertIsNone(
            second,
            msg="probe_pmtu while a probe is in flight must return None.",
        )


class TestUdpPlpmtudAdapter__Ack(TestCase):
    """
    The probe-ack API: 'ack_probe' dispatches engine event.
    """

    def test__udp__plpmtud_adapter__ack_probe_clears_in_flight(self) -> None:
        """
        Ensure 'ack_probe' clears the in-flight slot so a
        subsequent 'probe_pmtu' call can reserve a new slot.

        Reference: RFC 8899 §5.1.3 (PROBE_COUNT reset on each ack).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        adapter.probe_pmtu(now=0.0)

        adapter.ack_probe(now=1.0)

        self.assertIsNone(
            adapter.in_flight_size,
            msg="ack_probe must clear the in-flight slot.",
        )

    def test__udp__plpmtud_adapter__ack_probe_advances_engine_state(self) -> None:
        """
        Ensure 'ack_probe' on a BASE-state engine transitions
        it to SEARCHING — the application's app-layer ACK
        confirms the BASE probe.

        Reference: RFC 8899 §5.2 (Base → Search on confirmation).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        adapter.probe_pmtu(now=0.0)

        adapter.ack_probe(now=1.0)

        self.assertIs(
            adapter.state,
            PmtuState.SEARCHING,
            msg="ack_probe on BASE must advance state to SEARCHING.",
        )

    def test__udp__plpmtud_adapter__ack_probe_without_in_flight_is_noop(self) -> None:
        """
        Ensure 'ack_probe' is a no-op when no probe is in
        flight — a stray ACK from the application must not
        affect engine state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        adapter.ack_probe(now=1.0)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="Stray ack_probe must NOT change engine state.",
        )


class TestUdpPlpmtudAdapter__Timeout(TestCase):
    """
    The probe-loss API: 'timeout_probe' dispatches engine event.
    """

    def test__udp__plpmtud_adapter__timeout_probe_clears_in_flight(self) -> None:
        """
        Ensure 'timeout_probe' clears the in-flight slot so
        the application can probe again.

        Reference: RFC 8899 §5.1.3 (PROBE_COUNT bookkeeping).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        adapter.probe_pmtu(now=0.0)

        adapter.timeout_probe(now=1.0)

        self.assertIsNone(
            adapter.in_flight_size,
            msg="timeout_probe must clear the in-flight slot.",
        )

    def test__udp__plpmtud_adapter__timeout_max_probes_enters_error(self) -> None:
        """
        Ensure MAX_PROBES consecutive timeout_probe calls
        enter the engine's ERROR state and clamp current_mtu
        to the family minimum.

        Reference: RFC 8899 §5.2 (black-hole detection enters Error).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        now = 0.0
        for _ in range(MAX_PROBES):
            adapter.probe_pmtu(now=now)
            now += 1.0
            adapter.timeout_probe(now=now)

        self.assertIs(
            adapter.state,
            PmtuState.ERROR,
            msg="MAX_PROBES consecutive timeout_probe calls must enter ERROR.",
        )
        self.assertEqual(
            adapter.current_mtu,
            MIN_PLPMTU__IP6,
            msg="ERROR-state clamp must drop current_mtu to MIN_PLPMTU__IP6.",
        )

    def test__udp__plpmtud_adapter__timeout_without_in_flight_is_noop(self) -> None:
        """
        Ensure 'timeout_probe' is a no-op when no probe is in
        flight — a stray timer fire from the application must
        not advance probe_count.

        Reference: RFC 4821 §7.5 (probe-loss only counts on actual probe).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)

        adapter.timeout_probe(now=1.0)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="Stray timeout_probe must NOT advance engine state.",
        )


class TestUdpPlpmtudAdapter__ClassicalPmtu(TestCase):
    """
    Classical-PMTUD pass-through.
    """

    def test__udp__plpmtud_adapter__on_classical_pmtu_shrinks_current(self) -> None:
        """
        Ensure on_classical_pmtu passes through and shrinks
        current_mtu — the UDP adapter shares the engine's
        ICMP-driven shrink behaviour with the TCP adapter.

        Reference: RFC 8201 §4 (PTB shrinks PLPMTU, never raises).
        """

        adapter = UdpPlpmtudAdapter(remote_ip_address=_IP6_DST, interface_mtu=1500)
        prior = adapter.current_mtu

        adapter.on_classical_pmtu(1280, now=0.0)

        self.assertLessEqual(
            adapter.current_mtu,
            prior,
            msg="on_classical_pmtu must not raise current_mtu above the prior value.",
        )
