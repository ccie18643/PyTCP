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
This module contains the RFC 5961 §3 challenge-ACK rate-limit
sliding-window truth-table integration tests (the dedicated
challenge_ack pin for the TCP timer-client migration §5.5
'_timer_armed' gate).

pytcp/tests/integration/protocols/tcp/test__tcp__session__challenge_ack_window.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp import tcp__constants
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


class TestTcpChallengeAckWindow(TcpTestCase):
    """
    The RFC 5961 §3 challenge-ACK rate-limit window truth-table
    tests (post-migration '_timer_armed("challenge_ack")' gate).
    """

    def _unacceptable_segment(self) -> bytes:
        """
        Build a fully-duplicate (seq below RCV.NXT) 1-byte
        segment — the canonical challenge-ACK trigger.
        """

        return build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,  # below RCV.NXT (= PEER__ISS + 1)
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X",
        )

    def test__challenge_ack__unarmed_emits_then_within_window_suppresses(self) -> None:
        """
        Ensure the first unacceptable segment elicits exactly one
        challenge ACK (gate unarmed) and an immediately-following
        one within the rate-limit window is suppressed (gate
        armed and unfired).

        Reference: RFC 5961 §3 (challenge-ACK rate limit, sliding window).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._advance(ms=200)

        first_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(
            len(first_tx),
            1,
            msg="An unacceptable segment with the gate unarmed MUST elicit one challenge ACK.",
        )

        second_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(
            len(second_tx),
            0,
            msg="A second unacceptable segment within the rate-limit window MUST be suppressed.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="The challenge-ACK burst MUST NOT change FSM state.",
        )

    def test__challenge_ack__re_emits_after_rate_limit_window_elapses(self) -> None:
        """
        Ensure that once the rate-limit window has fully elapsed
        the next unacceptable segment elicits a fresh challenge
        ACK (gate re-reads as unarmed and re-arms).

        Reference: RFC 5961 §3 (challenge-ACK rate limit, sliding window).
        """

        self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._advance(ms=200)

        first_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(len(first_tx), 1, msg="Setup invariant: first segment must emit a challenge ACK.")

        self._advance(ms=tcp__constants.TCP__CHALLENGE_ACK__RATE_LIMIT_MS)

        post_window_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(
            len(post_window_tx),
            1,
            msg="After the full rate-limit window elapses a fresh challenge ACK MUST be emitted.",
        )

    def test__challenge_ack__suppressed_at_window_boundary_minus_one_ms(self) -> None:
        """
        Ensure the rate-limit window expires at exactly
        'TCP__CHALLENGE_ACK__RATE_LIMIT_MS': one ms early the segment
        is still suppressed; at the boundary it is emitted. This
        pins the exact fire-ms the Phase-4 trigger flip must
        preserve.

        Reference: RFC 5961 §3 (challenge-ACK rate limit, sliding window).
        """

        self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._advance(ms=200)

        first_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(len(first_tx), 1, msg="Setup invariant: first segment must emit a challenge ACK.")

        self._advance(ms=tcp__constants.TCP__CHALLENGE_ACK__RATE_LIMIT_MS - 1)
        pre_boundary_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(
            len(pre_boundary_tx),
            0,
            msg="One ms before the window elapses the challenge ACK MUST still be suppressed.",
        )

        self._advance(ms=1)
        boundary_tx = self._drive_rx(frame=self._unacceptable_segment())
        self.assertEqual(
            len(boundary_tx),
            1,
            msg=(
                "At exactly TCP__CHALLENGE_ACK__RATE_LIMIT_MS the window has elapsed "
                "and a challenge ACK MUST be emitted."
            ),
        )
