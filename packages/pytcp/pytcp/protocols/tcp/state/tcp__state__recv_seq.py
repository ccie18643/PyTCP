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
This module contains the per-session receive-side sequence-pointer
state container, covering the RFC 9293 §3.4 modular receive-window
pointers (IRS / RCV.NXT / RCV.UNA).

pytcp/protocols/tcp/state/tcp__state__recv_seq.py

ver 3.0.9
"""

from dataclasses import dataclass

from pytcp.protocols.tcp.tcp__seq import Seq32, lt32


@dataclass(slots=True)
class RecvSeqState:
    """
    Per-session receive-side seq state. Owned by 'TcpSession';
    set on handshake by the FSM SYN_SENT / SYN_RCVD entries and
    advanced per-segment in the receive pipeline.

    All fields are 32-bit modular per RFC 9293 §3.4.
    """

    # RFC 9293 §3.4 IRS — peer's initial receive sequence (i.e.
    # peer's ISS captured from the inbound SYN). Set once at
    # handshake; baseline for RCV.NXT / RCV.UNA on session entry.
    ini: Seq32 = 0

    # RFC 9293 §3.4 RCV.NXT — next receive seq expected from peer.
    # Advances on every accepted in-order segment (modular max
    # against the segment's end_seq).
    nxt: Seq32 = 0

    # RFC 9293 §3.4 RCV.UNA — left edge of pending-ACK window.
    # 'RCV.UNA != RCV.NXT' is the gate '_delayed_ack' uses to
    # decide whether an ACK still needs to be emitted; reset to
    # RCV.NXT on every outbound ACK-bearing segment.
    una: Seq32 = 0

    def reset_to(self, *, irs: Seq32) -> None:
        """
        Anchor IRS / RCV.NXT / RCV.UNA at the supplied IRS at
        handshake-prep time.

        Reference: RFC 9293 §3.4 (IRS-anchored receive window).
        """

        self.ini = irs
        self.nxt = irs
        self.una = irs

    def advance_nxt(self, *, seg_end: Seq32) -> None:
        """
        Advance RCV.NXT to 'seg_end' iff seg_end is strictly
        ahead in modular order. RFC 9293 §3.4 mandates the
        modular comparison so a stale-duplicate segment whose
        tail lies BEFORE current RCV.NXT cannot rewind the
        window.

        Reference: RFC 9293 §3.4 (modular RCV.NXT advance).
        Reference: RFC 9293 §3.10.7.4 (no-rewind protection).
        """

        if lt32(self.nxt, seg_end):
            self.nxt = seg_end
