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
This module contains integration tests for the RFC 6582 §3.2
post-RTO 'recover' marker decay in the inbound cum-ACK pipeline
('TcpAckProcessor'). The marker ('CongestionControlState.
recover_seq') is armed to SND.MAX on every RTO and must persist
until a cum-ACK genuinely advances SND.UNA to or past it, so
post-RTO dup-ACK bursts cannot spuriously re-enter fast
retransmit before the cumulative ACK has crossed the marker.

These tests pin the corner the broad TCP integration suite
exercises but does not assert to exact value: a partial cum-ACK
below the marker must leave 'recover_seq' intact (the 'and' gate
in 'recover_seq != 0 and ge32(SND.UNA, recover_seq)'), and a
cum-ACK that reaches the marker must clear it.

packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__recover_marker.py

ver 3.0.9
"""

from typing import cast, override

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__constants import TCP__RTO__INITIAL_MS
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000
_PEER__ISS: int = 0x0000_2000


class TestTcpSessionRecoverMarkerDecay(TcpTestCase):
    """
    The RFC 6582 §3.2 post-RTO 'recover' marker decay tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and drive an active TCP session into
        ESTABLISHED, then put 400 bytes of data in flight and
        trigger an RTO so the post-RTO 'recover' marker is armed
        to SND.MAX for every test in this class.
        """

        super().setUp()
        self._session = self._drive_handshake_to_established(
            iss=_LOCAL__ISS,
            peer_iss=_PEER__ISS,
        )
        self._session.send(data=b"X" * 400)
        # TX fires; SND.MAX advances past the 400-byte write.
        self._advance(ms=1)
        self._snd_max = self._session._snd_seq.max
        # Advance past the initial RTO so the retransmit timer
        # fires: the retransmitter arms 'recover_seq = SND.MAX'.
        self._advance(ms=TCP__RTO__INITIAL_MS + 1)

    def _peer_cum_ack(self, *, ack: int) -> bytes:
        """
        Build a bare peer cum-ACK segment carrying the supplied
        acknowledgement number.
        """

        session = self._session
        return build_tcp4(
            src_ip=cast(Ip4Address, session._remote_ip_address),
            dst_ip=cast(Ip4Address, session._local_ip_address),
            sport=session._remote_port,
            dport=session._local_port,
            seq=_PEER__ISS + 1,
            ack=ack & 0xFFFF_FFFF,
            flags=("ACK",),
            win=64240,
        )

    def test__tcp__recover_marker__rto_arms_marker_to_snd_max(self) -> None:
        """
        Ensure the post-RTO retransmit arms the 'recover' marker
        to exactly SND.MAX, the precondition the decay gate
        depends on.

        Reference: RFC 6582 §3.2 (recover := highest SND.MAX at RTO).
        """

        self.assertEqual(
            self._session._cc.recover_seq,
            self._snd_max,
            msg="The RTO retransmit must arm 'recover_seq' to exactly SND.MAX.",
        )

    def test__tcp__recover_marker__partial_ack_below_marker_keeps_it_armed(self) -> None:
        """
        Ensure a partial cum-ACK that advances SND.UNA but stays
        strictly below the post-RTO 'recover' marker leaves the
        marker armed, so the fast-retransmit entry gate is not
        prematurely re-opened. This pins the 'and' in
        'recover_seq != 0 and ge32(SND.UNA, recover_seq)' against
        an 'or' edit that would clear the marker on the first
        advancing cum-ACK regardless of whether it reached the
        marker.

        Reference: RFC 6582 §3.2 (recover marker survives a partial ACK).
        """

        session = self._session
        partial_ack = (_LOCAL__ISS + 1 + 100) & 0xFFFF_FFFF

        self._drive_rx(frame=self._peer_cum_ack(ack=partial_ack))

        self.assertEqual(
            session._snd_seq.una,
            partial_ack,
            msg="The partial cum-ACK must advance SND.UNA to the acknowledged byte.",
        )
        self.assertEqual(
            session._cc.recover_seq,
            self._snd_max,
            msg=(
                "A partial cum-ACK below the 'recover' marker must NOT "
                "clear it — the decay gate is 'recover_seq != 0 AND "
                "ge32(SND.UNA, recover_seq)', not an OR."
            ),
        )

    def test__tcp__recover_marker__cum_ack_reaching_marker_clears_it(self) -> None:
        """
        Ensure a cum-ACK whose acknowledgement number reaches the
        post-RTO 'recover' marker clears it to zero, re-opening
        the fast-retransmit entry gate for the next congestion
        episode. This pins the marker-clear assignment and the
        'ge32(SND.UNA, recover_seq)' comparison.

        Reference: RFC 6582 §3.2 step 4 (recover marker decays once reached).
        """

        session = self._session

        self._drive_rx(frame=self._peer_cum_ack(ack=self._snd_max))

        self.assertEqual(
            session._snd_seq.una,
            self._snd_max,
            msg="The full cum-ACK must advance SND.UNA to SND.MAX.",
        )
        self.assertEqual(
            session._cc.recover_seq,
            0,
            msg="A cum-ACK reaching the 'recover' marker must clear it to zero.",
        )
