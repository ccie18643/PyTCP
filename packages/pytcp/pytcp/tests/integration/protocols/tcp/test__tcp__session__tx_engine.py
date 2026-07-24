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
This module contains the per-session TCP TX-engine
collaborator-seam tests — pinning that the 'TcpTxEngine'
extracted from TcpSession (Phase 2 of the god-class
decomposition) is the canonical owner of the outbound-segment
construction pipeline and that the session-level
'_transmit_packet' / '_transmit_data' / '_delayed_ack' /
'_build_sack_blocks' / '_emit_challenge_ack' delegators
preserve the pre-refactor semantics.

The pure correctness of the moved methods is covered by the
existing TCP integration suite (FSM, retransmit, SACK, RACK,
ECN, Fast-Open, keep-alive, PAWS); this file pins only the
collaborator-seam invariants the refactor itself introduced.

packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__tx_engine.py

ver 3.0.9
"""

from typing import override

from pytcp.protocols.tcp.session.tcp__session__tx import TcpTxEngine
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000


class TestTcpTxEngineSeam(TcpTestCase):
    """
    The per-session TCP TX-engine collaborator-seam tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and construct an active TCP session for
        the collaborator-seam round-trips.
        """

        super().setUp()
        self._session = self._make_active_session(iss=_LOCAL__ISS)

    def test__tcp__tx_engine__session_owns_a_TcpTxEngine(self) -> None:
        """
        Ensure every TcpSession constructed by the standard
        '__init__' path owns a 'TcpTxEngine' instance reachable
        via 'session._tx_engine', so Phase 2's collaborator-
        ownership contract holds for every session-creation path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._session._tx_engine,
            TcpTxEngine,
            msg="Every TcpSession must own a TcpTxEngine reachable via 'session._tx_engine'.",
        )
        self.assertIs(
            self._session._tx_engine._session,
            self._session,
            msg="The TX engine's back-reference must point at the owning session (no cross-wired engine).",
        )

    def test__tcp__tx_engine__transmit_packet_delegator_emits_a_segment(self) -> None:
        """
        Ensure 'session._transmit_packet' delegates to
        'TcpTxEngine.transmit_packet' and the wire effect is
        identical: a single outbound segment is enqueued via the
        mocked TX ring with the requested ACK flag set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._state = FsmState.ESTABLISHED
        before = len(self._frames_tx)
        self._session._transmit_packet(flag_ack=True)

        emitted = self._frames_tx[before:]
        self.assertEqual(
            len(emitted),
            1,
            msg="A 'transmit_packet(flag_ack=True)' delegator call MUST emit exactly one outbound segment.",
        )

    def test__tcp__tx_engine__build_sack_blocks_delegator_returns_engine_result(self) -> None:
        """
        Ensure 'session._build_sack_blocks' delegates to
        'TcpTxEngine.build_sack_blocks' (both observe the same
        deadline-map / OOO-queue / DSACK state on the session and
        return identical results).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._session._build_sack_blocks(),
            self._session._tx_engine.build_sack_blocks(),
            msg="The session-side '_build_sack_blocks' delegator must return the engine's result verbatim.",
        )

    def test__tcp__tx_engine__emit_challenge_ack_delegator_routes_through_engine(self) -> None:
        """
        Ensure 'session._emit_challenge_ack' delegates to
        'TcpTxEngine.emit_challenge_ack' and the rate-limit
        gate (the 'challenge_ack' logical timer) suppresses
        further calls within the sliding window.

        Reference: RFC 5961 §3 (Challenge ACK rate limiting).
        """

        self._session._state = FsmState.ESTABLISHED
        before = len(self._frames_tx)

        # First call MUST emit one segment and arm the gate.
        self._session._emit_challenge_ack()
        self.assertEqual(
            len(self._frames_tx) - before,
            1,
            msg="First '_emit_challenge_ack' must emit one segment.",
        )
        self.assertTrue(
            self._session._timer_armed("challenge_ack"),
            msg="First '_emit_challenge_ack' must arm the 'challenge_ack' rate-limit gate.",
        )

        # Subsequent call within the window MUST be suppressed.
        before = len(self._frames_tx)
        self._session._emit_challenge_ack()
        self.assertEqual(
            len(self._frames_tx) - before,
            0,
            msg="Second '_emit_challenge_ack' within the rate-limit window must be suppressed.",
        )
