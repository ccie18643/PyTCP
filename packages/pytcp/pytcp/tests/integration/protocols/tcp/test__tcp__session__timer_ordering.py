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
This module contains the Phase-3 regression nets for the TCP
timer-client migration: the per-state timer-handler ordering pin
(retransmit -> transmit -> delayed_ack -> keepalive -> rack ->
tlp) and the §5.4 '_transmit_data' no-armed-timer gap audit.

pytcp/tests/integration/protocols/tcp/test__tcp__session__timer_ordering.py

ver 3.0.9
"""

from collections.abc import Callable

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

PEER__WIN: int = 64240

# The §4.3 ESTABLISHED timer-handler tick sequence. Phase 4
# changes ONLY the trigger (when the handler runs), never the
# handler body; this order is the invariant the trigger flip
# must preserve.
_ESTABLISHED_TICK_ORDER: tuple[str, ...] = (
    "_retransmit_packet_timeout",
    "_transmit_data",
    "_delayed_ack",
    "_keepalive_tick",
    "_rack_reorder_tick",
    "_tlp_pto_tick",
)


class TestTcpTimerHandlerOrdering(TcpTestCase):
    """
    The per-state timer-handler tick-ordering pin (Phase-4
    Rule-4 regression net).
    """

    def test__timer_ordering__established_tick_runs_canonical_sequence(self) -> None:
        """
        Ensure one ESTABLISHED timer service runs the tick
        methods in exactly the retransmit -> transmit ->
        delayed_ack -> keepalive -> rack -> tlp order. This is
        the load-bearing invariant (retransmit-before-transmit,
        rack-before-tlp) the Phase-4 coalesced trigger must
        preserve.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        order: list[str] = []

        def _make_recorder(name: str, original: Callable[[], None]) -> Callable[[], None]:
            def _recorder() -> None:
                order.append(name)
                original()

            return _recorder

        for name in _ESTABLISHED_TICK_ORDER:
            original = getattr(session, name)
            setattr(session, name, _make_recorder(name, original))

        self._advance(ms=1)

        self.assertEqual(
            tuple(order),
            _ESTABLISHED_TICK_ORDER,
            msg=(
                "One ESTABLISHED timer service MUST invoke the tick "
                f"methods in the canonical order {_ESTABLISHED_TICK_ORDER}. "
                f"Got {tuple(order)}."
            ),
        )


class TestTcpTransmitDataGapAudit(TcpTestCase):
    """
    The §5.4 '_transmit_data' no-armed-timer gap audit: whenever
    there is data the stack still needs to push, at least one
    logical timer is armed, so the Phase-4 coalesced service
    handle is armed and '_transmit_data' is serviced (no
    'tx-drain' timer is needed).
    """

    def test__gap_audit__in_flight_data_keeps_retransmit_armed(self) -> None:
        """
        Ensure data in flight (SND.UNA != SND.MAX) always has the
        retransmit timer armed, so the coalesced service handle
        is armed and '_transmit_data' continues to be serviced.

        Reference: RFC 6298 §5.1 (retransmit timer armed while data outstanding).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.send(data=b"payload-in-flight")
        self._advance(ms=1)

        self.assertNotEqual(
            session._snd_seq.una,
            session._snd_seq.max,
            msg="Setup invariant: there must be data in flight.",
        )
        self.assertTrue(
            session._timer_armed("retransmit"),
            msg=(
                "With data in flight the retransmit timer MUST be "
                "armed — otherwise the Phase-4 coalesced service "
                "handle would be unarmed and '_transmit_data' would "
                "stall."
            ),
        )

    def test__gap_audit__zero_window_pending_data_keeps_persist_armed(self) -> None:
        """
        Ensure buffered data that cannot be sent because the peer
        advertised a zero window always has the persist timer
        armed, so '_transmit_data' is serviced to emit the
        zero-window probe.

        Reference: RFC 9293 §3.8.6.1 (zero-window probing / persist timer).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.send(data=b"first")
        self._advance(ms=1)

        peer_zero_window = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 5,
            flags=("ACK",),
            win=0,
        )
        self._drive_rx(frame=peer_zero_window)
        self.assertEqual(
            session._win.snd_wnd,
            0,
            msg="Setup invariant: peer must have shut the window.",
        )

        session.send(data=b"x" * 10)
        self._advance(ms=1)

        self.assertGreater(
            len(session._tx.buffer),
            0,
            msg="Setup invariant: there must be unsendable buffered data.",
        )
        self.assertTrue(
            session._timer_armed("persist"),
            msg=(
                "With buffered data and a zero peer window the "
                "persist timer MUST be armed — otherwise the "
                "Phase-4 coalesced service handle would be unarmed "
                "and the zero-window probe would never fire."
            ),
        )

    def test__gap_audit__close_wait_in_flight_data_keeps_retransmit_armed(self) -> None:
        """
        Ensure the no-gap invariant also holds in CLOSE_WAIT: a
        send after the peer's FIN keeps the retransmit timer
        armed while the data is in flight.

        Reference: RFC 6298 §5.1 (retransmit timer armed while data outstanding).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup invariant: peer FIN must transition the session to CLOSE_WAIT.",
        )

        session.send(data=b"close-wait-data")
        self._advance(ms=1)

        self.assertNotEqual(
            session._snd_seq.una,
            session._snd_seq.max,
            msg="Setup invariant: there must be data in flight in CLOSE_WAIT.",
        )
        self.assertTrue(
            session._timer_armed("retransmit"),
            msg="CLOSE_WAIT with data in flight MUST keep the retransmit timer armed.",
        )
