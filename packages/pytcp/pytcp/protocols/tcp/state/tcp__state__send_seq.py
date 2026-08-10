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
This module contains the per-session send-side sequence-pointer
state container, covering the RFC 9293 §3.4 modular send-window
pointers (ISS / SND.UNA / SND.NXT / SND.MAX) plus the FIN seq
bookkeeping and the RFC 1122 §4.2.3.4 Nagle/Minshall partial-
segment pointer.

pytcp/protocols/tcp/state/tcp__state__send_seq.py

ver 3.0.10
"""

from dataclasses import dataclass

from pytcp.protocols.tcp.tcp__seq import Seq32, add32, lt32


@dataclass(slots=True)
class SendSeqState:
    """
    Per-session send-side seq state. Owned by 'TcpSession';
    mutated by the FSM transitions on session establishment and
    by the per-segment send/ack hooks throughout
    '_phase4_advance_send_state' / '_phase1_cum_ack_side_effects'.

    All fields are 32-bit modular per RFC 9293 §3.4. Helper
    methods preserve modular arithmetic via 'add32' / 'lt32'.
    """

    # RFC 9293 §3.4 ISS — initial send sequence number, set once
    # at handshake-prep time (active-open SYN_SENT entry or
    # passive-open SYN_RCVD entry) by 'compute_iss'. Used as the
    # baseline for SND.NXT / SND.MAX / SND.UNA / SND.SML at session
    # construction and as the anchor for tx_buffer_seq_mod.
    ini: Seq32 = 0

    # RFC 9293 §3.4 SND.UNA — left edge of the send window;
    # advances on cum-ACKs that strictly exceed it (modular).
    una: Seq32 = 0

    # RFC 9293 §3.4 SND.NXT — next byte to send. Advances on
    # every transmitted byte (data / SYN / FIN); rewound to
    # SND.UNA on RTO/FR retransmit; bumped via add32 on every
    # outbound segment in '_phase4_advance_send_state'.
    nxt: Seq32 = 0

    # RFC 9293 §3.4 SND.MAX (high-water mark) — the largest
    # SND.NXT we have ever observed. Used for flight-size
    # computation and as the marker for F-RTO / RACK
    # disambiguation.
    max: Seq32 = 0

    # RFC 9293 §3.10.7.x FIN seq tracking. 'fin' holds the seq
    # at which the FIN flag was sent (so the eventual ACK that
    # covers it can transition the session out of FIN_WAIT_1 /
    # CLOSING / LAST_ACK). 'fin_sent' is the gate flag set at
    # FIN-emission time so the application's CLOSE syscall is
    # idempotent.
    fin: Seq32 = 0
    fin_sent: bool = False

    # RFC 1122 §4.2.3.4 Nagle/Minshall partial-segment seq.
    # The seq AFTER the most recent sub-MSS partial we sent;
    # Minshall's modification defers a subsequent partial
    # while a previous partial is still unacknowledged. A
    # value strictly less than SND.UNA means "no partial in
    # flight."
    sml: Seq32 = 0

    def reset_to(self, *, iss: Seq32) -> None:
        """
        Initialise all four core seq pointers to the supplied ISS
        value at handshake-prep time. Called once per session.

        Reference: RFC 9293 §3.4 (ISS-anchored send window).
        """

        self.ini = iss
        self.una = iss
        self.nxt = iss
        self.max = iss
        self.sml = iss

    def advance_nxt(self, *, seq: Seq32, data_len: int, flag_syn: bool, flag_fin: bool) -> None:
        """
        Advance SND.NXT past the bytes consumed by the segment
        rooted at 'seq' carrying 'data_len' bytes plus the
        supplied SYN/FIN flag-seqs (each consumes one seq).
        Modular per RFC 9293 §3.4.

        Reference: RFC 9293 §3.4 (modular SND.NXT advance).
        """

        self.nxt = add32(seq, data_len, flag_syn, flag_fin)

    def bump_max_to_nxt(self) -> None:
        """
        Move SND.MAX forward to SND.NXT iff SND.NXT is strictly
        ahead of it in modular order. Plain 'max()' is wrong
        across the 32-bit wrap; this uses 'lt32' to compare
        modularly.

        Reference: RFC 9293 §3.4 (modular SND.MAX bump).
        """

        if lt32(self.max, self.nxt):
            self.max = self.nxt

    def record_fin(self) -> None:
        """
        Stash SND.NXT as the FIN seq and set 'fin_sent' True.
        Called from '_phase4_advance_send_state' once a FIN has
        been emitted. Idempotent CLOSE relies on the fin_sent
        gate.

        Reference: RFC 9293 §3.10.7.4 (FIN bookkeeping).
        """

        self.fin = self.nxt
        self.fin_sent = True

    def bytes_acked(self, *, new_una: Seq32) -> int:
        """
        Compute the modular bytes-acked delta when the cum-ACK
        advances SND.UNA from its current value to 'new_una'.
        Caller is responsible for the lt32(una, new_una) gate
        before calling.

        Reference: RFC 9293 §3.4 (modular bytes-acked).
        """

        return (new_una - self.una) & 0xFFFF_FFFF
