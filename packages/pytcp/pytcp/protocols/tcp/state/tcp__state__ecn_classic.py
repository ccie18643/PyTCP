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
This module contains the per-session classic ECN (RFC 3168)
sender + receiver state container. Holds the bilateral
'enabled' flag, the receiver-side CE-echo flag, the sender-side
CWR-confirmation flag, and the §6.1.2 once-per-RTT recovery
point.

pytcp/protocols/tcp/state/tcp__state__ecn_classic.py

ver 3.0.10
"""

from dataclasses import dataclass

from pytcp.protocols.tcp.tcp__seq import Seq32


@dataclass(slots=True)
class ClassicEcnState:
    """
    Per-session RFC 3168 classic ECN state. Owned by 'TcpSession';
    mutated by the receiver-side CE-echo path, the sender-side
    CWR-confirmation path, and the inbound-ECE response branch.

    Mutually exclusive with AccEcnState.enabled (RFC 9768
    §3.1.1: AccECN-setup SYN+ACK supersedes RFC 3168 ECE-only
    SYN+ACK once both sides advertise AccECN).
    """

    # RFC 3168 §6.1.1 bilateral-success flag. True post-handshake
    # when both sides advertised classic ECN. While True,
    # outbound data carries IP ECT(0); inbound CE marks are
    # echoed via ECE on the next outbound segment; inbound ECE
    # triggers cwnd reduction per §6.1.2.
    enabled: bool = False

    # RFC 3168 §6.1.2 receiver-side CE-echo flag. Set True when
    # an inbound segment arrives with the IP CE codepoint;
    # every subsequent outbound TCP segment carries ECE as the
    # wire echo back to the sender. Cleared when the sender
    # confirms cwnd reduction by setting CWR on a subsequent
    # segment.
    send_ece: bool = False

    # RFC 3168 §6.1.2 sender-side state. 'send_cwr' is True
    # after responding to an inbound ECE (cwnd / ssthresh
    # halved); the next outbound data segment carries CWR as
    # the wire confirmation, then the flag clears.
    send_cwr: bool = False

    # RFC 3168 §6.1.2 one-shot recovery-point gate: SND.NXT at
    # the moment of the ECE response. Subsequent ECEs are
    # ignored until SND.UNA crosses this point so a single
    # congestion episode halves cwnd at most once per RTT.
    recovery_point: Seq32 = 0

    def arm_cwr_response(self, *, snd_nxt: Seq32) -> None:
        """
        Mark the per-RTT recovery point at SND.NXT and arm the
        CWR-confirmation flag so the next outbound data segment
        carries CWR. The CC-side response (cwnd / ssthresh
        halving) lives on TcpSession because it touches
        CongestionControlState.

        Reference: RFC 3168 §6.1.2 (ECE response → CWR + recovery point).
        """

        self.send_cwr = True
        self.recovery_point = snd_nxt

    def consume_cwr(self) -> bool:
        """
        Return True iff CWR should be set on the next outbound
        segment, and clear the flag so subsequent segments stay
        unmarked. Caller is responsible for the 'enabled' and
        'data segment' gates before calling.

        Reference: RFC 3168 §6.1.2 (CWR is cleared on emission).
        """

        if self.send_cwr:
            self.send_cwr = False
            return True
        return False
