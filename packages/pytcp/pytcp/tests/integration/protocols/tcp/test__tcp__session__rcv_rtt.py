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
Integration tests for the receiver-side RTT estimator (Tier-3 Track R,
R1). On an inbound new-data segment carrying a valid RFC 7323 TSecr, the
session folds 'now_ms - TSecr' into '_rcv_rtt' — the RTT measurement DRS
needs even on a pure receiver (which only sends ACKs, so the sender SRTT
never gets a sample). Timestamps-gated for the first pass.

pytcp/tests/integration/protocols/tcp/test__tcp__session__rcv_rtt.py

ver 3.0.8
"""

from pytcp.protocols.tcp.session import TcpSession
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_PORT = 12345
_REMOTE_PORT = 80
_PEER_ISS = 5000
_LOCAL_ISS = 1000


class TestTcpSessionRcvRtt(TcpTestCase):
    """
    The receiver-side RTT estimator RX-path tests.
    """

    def _establish_with_tsopt(self) -> TcpSession:
        """
        Drive an active-open handshake with bilateral timestamps and
        advance the virtual clock past the sampled RTTs so 'now_ms -
        TSecr' stays positive.
        """

        session = self._drive_handshake_to_established(
            iss=_LOCAL_ISS,
            peer_iss=_PEER_ISS,
            peer_tsval=7000,
            peer_tsecr=0,
        )
        assert session._ts.send_ts, "Setup: bilateral TSopt negotiation must succeed."
        self._advance(ms=200)
        return session

    def _peer_data(self, *, seq: int, tsval: int, tsecr: int, payload: bytes) -> bytes:
        """
        Build an inbound data segment carrying the supplied TSval /
        TSecr and payload.
        """

        return build_tcp4(
            sport=_REMOTE_PORT,
            dport=_LOCAL_PORT,
            seq=seq,
            ack=_LOCAL_ISS + 1,
            flags=("ACK",),
            win=64240,
            tsval=tsval,
            tsecr=tsecr,
            payload=payload,
        )

    def test__rcv_rtt__first_data_segment_seeds_estimate(self) -> None:
        """
        Ensure an inbound new-data segment whose TSecr was sent one
        round trip ago seeds the receiver RTT estimate with
        'now_ms - TSecr'.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        session = self._establish_with_tsopt()
        now = self._timer.now_ms
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 1, tsval=7001, tsecr=now - 40, payload=b"X" * 100))

        self.assertEqual(
            session._rcv_rtt.rtt_ms,
            40,
            msg="The first data segment must seed the receiver RTT with now_ms - TSecr.",
        )

    def test__rcv_rtt__second_segment_folds_ewma(self) -> None:
        """
        Ensure a second new-data segment with a fresh TSecr folds into
        the receiver RTT via the alpha = 1/8 EWMA.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        session = self._establish_with_tsopt()
        now = self._timer.now_ms
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 1, tsval=7001, tsecr=now - 40, payload=b"X" * 100))
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 101, tsval=7002, tsecr=now - 80, payload=b"Y" * 100))

        # (7 * 40 + 80) // 8 == 45.
        self.assertEqual(
            session._rcv_rtt.rtt_ms,
            45,
            msg="A second fresh-TSecr sample must fold via the 1/8 EWMA.",
        )

    def test__rcv_rtt__no_timestamps_leaves_estimate_unset(self) -> None:
        """
        Ensure a connection without bilateral timestamps never
        populates the receiver RTT estimate — the first pass is
        timestamps-gated.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        session = self._drive_handshake_to_established(iss=_LOCAL_ISS, peer_iss=_PEER_ISS)
        assert not session._ts.send_ts, "Setup: no bilateral TSopt without peer TSval."
        self._advance(ms=200)
        self._drive_rx(
            frame=build_tcp4(
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS + 1,
                ack=_LOCAL_ISS + 1,
                flags=("ACK",),
                win=64240,
                payload=b"X" * 100,
            )
        )

        self.assertIsNone(
            session._rcv_rtt.rtt_ms,
            msg="Without timestamps the receiver RTT estimate must stay unset.",
        )

    def test__rcv_rtt__duplicate_tsecr_yields_single_sample(self) -> None:
        """
        Ensure two new-data segments echoing the same TSecr contribute
        only one RTT sample, so a within-RTT burst does not overweight
        the estimate.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        session = self._establish_with_tsopt()
        now = self._timer.now_ms
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 1, tsval=7001, tsecr=now - 40, payload=b"X" * 100))
        # Same TSecr, fresh data — the second sample must be ignored.
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 101, tsval=7002, tsecr=now - 40, payload=b"Y" * 100))

        self.assertEqual(
            session._rcv_rtt.rtt_ms,
            40,
            msg="A repeated TSecr must not contribute a second sample.",
        )
