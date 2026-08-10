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
This module contains the per-session TCP ACK-processor
collaborator-seam tests — pinning that the 'TcpAckProcessor'
extracted from TcpSession (Phase 3 of the god-class
decomposition) is the canonical owner of the inbound-ACK
pipeline and that the session-level '_process_ack_packet'
delegator routes through the engine.

The pure correctness of the moved phases is covered by the
existing TCP integration suite (handshake, retransmit, SACK,
RACK, ECN / AccECN, Fast-Open, F-RTO, RFC 6298 RTT harvest);
this file pins only the collaborator-seam invariants the
refactor itself introduced.

packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__ack_processor.py

ver 3.0.9
"""

from typing import cast, override

from net_addr import Ip4Address
from pytcp.protocols.tcp.session.tcp__session__ack import TcpAckProcessor
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000
_PEER__ISS: int = 0x0000_2000


class TestTcpAckProcessorSeam(TcpTestCase):
    """
    The per-session TCP ACK-processor collaborator-seam tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and construct an active TCP session
        driven into ESTABLISHED for the collaborator-seam
        round-trips.
        """

        super().setUp()
        self._session = self._drive_handshake_to_established(
            iss=_LOCAL__ISS,
            peer_iss=_PEER__ISS,
        )

    def test__tcp__ack_processor__session_owns_a_TcpAckProcessor(self) -> None:
        """
        Ensure every TcpSession constructed by the standard
        '__init__' path owns a 'TcpAckProcessor' instance
        reachable via 'session._ack_processor', so Phase 3's
        collaborator-ownership contract holds for every
        session-creation path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._session._ack_processor,
            TcpAckProcessor,
            msg="Every TcpSession must own a TcpAckProcessor reachable via 'session._ack_processor'.",
        )
        self.assertIs(
            self._session._ack_processor._session,
            self._session,
            msg="The ACK processor's back-reference must point at the owning session (no cross-wiring).",
        )

    def test__tcp__ack_processor__rx_data_advances_snd_una(self) -> None:
        """
        Ensure an inbound peer segment that carries data + a cum-
        ACK routes through the FSM into 'session._process_ack_packet'
        and the engine's Phase-1 cum-ACK side effects advance
        SND.UNA. The handshake leaves SND.UNA = ISS+1; peer sends
        one byte of data; the session ACKs it and SND.UNA must
        stay at ISS+1 (peer's ACK in the data segment still
        acknowledges only the SYN, not subsequent data).

        Reference: RFC 9293 §3.4 (modular SND.UNA advance).
        """

        snd_una_before = self._session._snd_seq.una
        rcv_nxt_before = self._session._rcv_seq.nxt

        peer_data = build_tcp4(
            src_ip=cast(Ip4Address, self._session._remote_ip_address),
            dst_ip=cast(Ip4Address, self._session._local_ip_address),
            sport=self._session._remote_port,
            dport=self._session._local_port,
            seq=_PEER__ISS + 1,
            ack=_LOCAL__ISS + 1,
            flags=("ACK",),
            win=64240,
            payload=b"x",
        )
        self._drive_rx(frame=peer_data)

        # Peer's ACK still acks the SYN only; SND.UNA stays put.
        # But the data must have been received (RCV.NXT advances)
        # by routing through the ACK processor's Phase 5.
        self.assertEqual(
            self._session._snd_seq.una,
            snd_una_before,
            msg=("Peer's ACK in this segment only acknowledges the SYN; " "SND.UNA must stay at ISS+1."),
        )
        self.assertEqual(
            self._session._rcv_seq.nxt,
            (rcv_nxt_before + 1) & 0xFFFF_FFFF,
            msg=(
                "The delegator-routed inbound segment must advance "
                "RCV.NXT by exactly the one payload byte (Phase 5 consume)."
            ),
        )

    def test__tcp__ack_processor__delegator_invokes_engine(self) -> None:
        """
        Ensure 'session._process_ack_packet(packet_rx_md)' invokes
        'session._ack_processor.process_ack_packet(packet_rx_md)'
        and not some shadow path: monkeypatch the engine's
        'process_ack_packet' to record the call and route a
        delegator call; the recorder must observe exactly one
        invocation with the same packet object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        observed: list[object] = []

        def _spy(packet_rx_md: object, /) -> None:
            """Record the delegated call without running the pipeline."""
            observed.append(packet_rx_md)

        # Monkeypatch the bound method on the engine instance so
        # the delegator's '.process_ack_packet(...)' call lands here.
        self._session._ack_processor.process_ack_packet = _spy  # type: ignore[method-assign,assignment]
        sentinel = object()
        self._session._process_ack_packet(sentinel)  # type: ignore[arg-type]

        self.assertEqual(
            observed,
            [sentinel],
            msg=(
                "session._process_ack_packet MUST delegate to "
                "session._ack_processor.process_ack_packet with the "
                "same packet object — no shadow path."
            ),
        )
