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
This module contains integration tests for 'TcpSession' robustness
against malformed inbound TCP segments. The TCP parser handles the
checksum / structural-integrity layer (covered by parser unit
tests); this file covers the FSM's behaviour when the parser does
let a structurally-valid but semantically-malformed segment through
- e.g. illegal flag combinations like FIN+RST.

Reference RFCs:
    RFC 9293 §3.1        Control Bits semantics
    RFC 9293 §3.10.7.4   Synchronized state segment processing

pytcp/tests/integration/protocols/tcp/test__tcp__session__robustness__bad_segments.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__constants import TCP__DELAYED_ACK__DELAY_MS
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpRobustness__BadSegments(TcpTestCase):
    """
    Integration tests for 'TcpSession' robustness against malformed
    inbound TCP segments that the parser passes through but the FSM
    must reject (illegal flag combinations, etc.).
    """

    def test__bad_segments__fin_plus_rst_in_established_drops_silently(self) -> None:
        """
        Ensure that a segment carrying BOTH the FIN and RST flags
        is silently dropped on receipt in ESTABLISHED: state is
        unchanged, no segment is emitted in response, and
        'RCV.NXT' / 'SND.UNA' do not advance. FIN and RST encode
        mutually exclusive intents and no legitimate conformant
        peer sends both. The synchronized-state branches cleanly
        separate FIN and RST so the segment falls through.

        Reference: RFC 9293 §3.1 (control-bit semantics).
        Reference: RFC 9293 §3.10.7.4 (synchronized state segment processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_seq.una
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer sends FIN+RST+ACK - the malformed flag combination.
        peer_fin_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_fin_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "A FIN+RST segment in ESTABLISHED MUST produce no "
                "outbound segment - the flag combination is malformed "
                "per RFC 9293 §3.1 and must be silently dropped before "
                "any state-changing branch sees it."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=("State must remain ESTABLISHED after a FIN+RST drop - " "neither the FIN nor the RST is processed."),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg="'SND.UNA' must not advance on a dropped FIN+RST segment.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "'RCV.NXT' must not advance on a dropped FIN+RST "
                "segment - the FIN's potential one-byte consumption "
                "is forfeited because the segment is rejected at the "
                "branch-matching layer."
            ),
        )

    def test__bad_segments__all_zero_flags_segment_in_established_drops_silently(self) -> None:
        """
        Ensure a segment with no flags set (the all-zero flags
        byte) is silently dropped on receipt in ESTABLISHED:
        no outbound reply, state unchanged, SND.UNA / RCV.NXT
        unchanged. Once the connection is synchronized every
        segment the peer sends must carry an ACK piggyback;
        a flag-less segment is malformed, stale, or an attacker
        probe and the safe response is to drop without reply.

        Reference: RFC 9293 §3.10.7.4 (drop segment when ACK bit is off).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_seq.una
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer sends a flag-less segment.
        peer_no_flags = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=(),
            win=PEER__WIN,
        )
        no_flags_inline = self._drive_rx(frame=peer_no_flags)

        self.assertEqual(
            no_flags_inline,
            [],
            msg=(
                "An all-zero-flags segment in ESTABLISHED MUST "
                "produce no outbound reply - RFC 9293 §3.10.7.4: "
                "'If the ACK bit is off, drop the segment and "
                "return.'"
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED after a no-flags drop.",
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg="'SND.UNA' must not advance on a dropped no-flags segment.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg="'RCV.NXT' must not advance on a dropped no-flags segment.",
        )

    def test__bad_segments__ecn_flags_accepted_and_not_echoed(self) -> None:
        """
        Ensure a non-ECN endpoint accepts a segment carrying
        ECE / CWR (the segment is processed normally and data
        is delivered) and does NOT echo ECE / CWR in the
        outbound ACK. PyTCP never negotiates ECN on the SYN
        handshake, so ECE / CWR on any inbound segment must be
        treated as having no effect, and the outbound reply
        must not set those bits.

        Reference: RFC 3168 §6.1.1 (non-ECN endpoint MUST NOT echo ECE/CWR).
        Reference: RFC 9293 §3.1 (control-bit semantics).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends a data segment with ECE+CWR set despite us
        # never having negotiated ECN on the SYN handshake.
        peer_payload = b"hello"
        peer_data_with_ecn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH", "ECE", "CWR"),
            win=PEER__WIN,
            payload=peer_payload,
        )
        ecn_inline = self._drive_rx(frame=peer_data_with_ecn)
        self.assertEqual(
            ecn_inline,
            [],
            msg=(
                "An ECN-marked data segment must follow the same "
                "delayed-ACK path as a plain data segment - no "
                "inline ACK fires for the first segment of a stream."
            ),
        )

        # Data was accepted and enqueued.
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg=(
                "Peer's data must be delivered to '_rx_buffer' even "
                "with ECE+CWR flags set. RFC 3168 §6.1.1 / RFC 9293 "
                "§3.1: non-ECN endpoint treats ECE/CWR as having no "
                "effect, processing the segment normally."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(peer_payload),
            msg="'RCV.NXT' must advance by len(peer_payload) after the data is enqueued.",
        )

        # Tick past the delayed-ACK boundary to fire the outbound ACK.
        ack_window_tx = self._advance(ms=TCP__DELAYED_ACK__DELAY_MS)
        self.assertEqual(
            len(ack_window_tx),
            1,
            msg=(
                f"Within {TCP__DELAYED_ACK__DELAY_MS} ms of receipt the delayed-"
                "ACK timer must fire exactly one outbound ACK."
            ),
        )

        # The ACK must NOT echo ECE / CWR - we never agreed to ECN.
        outbound_ack = self._parse_tx(ack_window_tx[0])
        self.assertEqual(
            outbound_ack.flags,
            frozenset({"ACK"}),
            msg=(
                "Outbound ACK must carry flags = {ACK} only - no ECE, "
                "no CWR. PyTCP did not negotiate ECN on the SYN "
                "handshake, so RFC 3168 §6.1.1 forbids us from "
                "setting ECE or CWR on any subsequent transmission."
            ),
        )
