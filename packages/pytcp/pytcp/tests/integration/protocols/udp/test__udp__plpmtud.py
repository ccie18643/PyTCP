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
Integration tests for the UDP-side PLPMTUD manual API
(UdpSocket.probe_pmtu / ack_probe / timeout_probe) shipped
in Phase 4 of the PLPMTUD plan. Exercises:

  * probe_pmtu emits a UDP datagram of the requested IP packet
    size on the wire (zero-padded payload).
  * ack_probe advances the engine state and clears in-flight.
  * timeout_probe × MAX_PROBES enters ERROR with min clamp.
  * probe_pmtu while one is in flight returns None.
  * probe_pmtu on an unconnected socket returns None.

pytcp/tests/integration/protocols/udp/test__udp__plpmtud.py

ver 3.0.9
"""

from pytcp.lib.plpmtud import MAX_PROBES, MIN_PLPMTU__IP4, PmtuState
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.udp_testcase import (
    HOST_A__IP4_ADDRESS,
    UdpTestCase,
)

_REMOTE_PORT = 5555


class TestUdpPlpmtud(UdpTestCase):
    """
    The UDP PLPMTUD manual probe API tests.
    """

    def test__udp__plpmtud__probe_pmtu_emits_sized_datagram(self) -> None:
        """
        Ensure 'probe_pmtu(size=N)' emits a UDP datagram on the
        wire whose total IP-packet size matches the requested N.

        Reference: RFC 8899 §6 (PL probe-packet generation).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )

        size = sock.probe_pmtu(size=1200)

        self.assertEqual(
            size,
            1200,
            msg="probe_pmtu(size=1200) must return 1200 (the chosen probe size).",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Exactly one outbound frame must be emitted by probe_pmtu.",
        )
        outbound = self._frames_tx[-1]
        # Frame layout: Ethernet(14) + IPv4 packet. IP packet
        # size = 1200 means the frame is 14 + 1200 = 1214 bytes.
        self.assertEqual(
            len(outbound),
            14 + 1200,
            msg="Probe frame must be Ethernet(14) + IPv4 packet of probe size.",
        )

    def test__udp__plpmtud__ack_probe_advances_state(self) -> None:
        """
        Ensure 'ack_probe' transitions the engine state from
        BASE to SEARCHING — the application's app-layer ACK
        confirms the BASE probe.

        Reference: RFC 8899 §5.2 (Base → Search on confirmation).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )
        sock.probe_pmtu(size=1200)

        sock.ack_probe()

        assert sock._plpmtud_adapter is not None
        self.assertIs(
            sock._plpmtud_adapter.state,
            PmtuState.SEARCHING,
            msg="ack_probe on BASE must advance state to SEARCHING.",
        )

    def test__udp__plpmtud__timeout_probe_count_enters_error(self) -> None:
        """
        Ensure MAX_PROBES consecutive timeout_probe calls
        enter the engine's ERROR state and clamp current_mtu
        to the IPv4 family minimum (576 bytes).

        Reference: RFC 8899 §5.2 (black-hole detection).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )

        for _ in range(MAX_PROBES):
            sock.probe_pmtu(size=1200)
            sock.timeout_probe()

        assert sock._plpmtud_adapter is not None
        self.assertIs(
            sock._plpmtud_adapter.state,
            PmtuState.ERROR,
            msg="MAX_PROBES consecutive timeouts must enter ERROR.",
        )
        self.assertEqual(
            sock._plpmtud_adapter.current_mtu,
            MIN_PLPMTU__IP4,
            msg="ERROR clamp must drop current_mtu to MIN_PLPMTU__IP4 (576).",
        )

    def test__udp__plpmtud__probe_pmtu_rejects_concurrent_probe(self) -> None:
        """
        Ensure 'probe_pmtu' returns None when an outstanding
        probe is already in flight — the single-outstanding
        invariant guarantees the application's app-layer ACK
        unambiguously maps to one probe.

        Reference: RFC 8899 §6 (probe loss recovery requires unambiguous ACK).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )
        first = sock.probe_pmtu(size=1200)
        self.assertEqual(first, 1200, msg="First probe_pmtu must succeed.")

        second = sock.probe_pmtu(size=1300)

        self.assertIsNone(
            second,
            msg="probe_pmtu while a probe is in flight must return None.",
        )

    def test__udp__plpmtud__probe_pmtu_unconnected_returns_none(self) -> None:
        """
        Ensure 'probe_pmtu' returns None for an unconnected
        UDP socket (no fixed destination) — PLPMTUD state is
        per-destination, so an unconnected socket has no
        meaningful probing target.

        Reference: RFC 8899 §3 #9 (per-destination state).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET4)
        # No remote_ip / remote_port supplied → unconnected.

        result = sock.probe_pmtu(size=1200)

        self.assertIsNone(
            result,
            msg="probe_pmtu on an unconnected socket must return None.",
        )
        self.assertEqual(
            len(self._frames_tx),
            0,
            msg="No frame must be emitted when probe_pmtu rejects the call.",
        )

    def test__udp__plpmtud__ack_then_reprobe_succeeds(self) -> None:
        """
        Ensure 'ack_probe' clears the in-flight slot so a
        subsequent 'probe_pmtu' call can reserve a new slot
        — chained probe / ack cycles drive the binary-search
        ladder forward.

        Reference: RFC 8899 §5.3 (search algorithm progression).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )
        sock.probe_pmtu(size=1200)
        sock.ack_probe()

        # After the BASE ack, a larger probe should succeed.
        second = sock.probe_pmtu(size=1400)

        self.assertEqual(
            second,
            1400,
            msg="After ack_probe, a fresh probe_pmtu call must succeed.",
        )
