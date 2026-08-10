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
This module contains the per-session RTT-sample tracker state
container, covering the RFC 6298 §4 single-pending-sample
discipline + the §5.7 idle-baseline timestamp.

pytcp/protocols/tcp/state/tcp__state__rtt_sample.py

ver 3.0.9
"""

from dataclasses import dataclass

from pytcp.protocols.tcp.tcp__seq import Seq32


@dataclass(slots=True)
class RttSampleState:
    """
    Per-session RTT-sample tracker. Owned by 'TcpSession';
    written at outbound-segment time (Phase 0 of TX), harvested
    at covering-ACK time (Phase 3 of RX).

    The §4 'one sample per RTT' rule is enforced by checking
    'seq is None' before recording a fresh sample. The §3 Karn
    flag ('retransmitted') is set when the sampled seq is
    retransmitted; the harvest path skips the rto_state update
    when the flag is True.
    """

    # RFC 6298 §4 in-flight sample seq. None means no sample is
    # pending; the next outbound sequence-consuming segment can
    # record one.
    seq: Seq32 | None = None

    # The 'now_ms' captured at sample-record time. Paired with
    # 'seq' for the eventual covering-ACK harvest.
    send_time_ms: int | None = None

    # RFC 6298 §3 Karn taint flag. Set True if the sampled seq
    # is retransmitted between record and harvest; the harvest
    # path then skips the rto_state update for this sample.
    retransmitted: bool = False

    # RFC 6298 §5.7 idle-baseline tracker. 'now_ms' refreshed on
    # every outbound sequence-consuming segment so the §5.7
    # idle-check has an accurate baseline. None on a fresh
    # session before any send has occurred (the §5.7 'first send'
    # gate).
    last_send_time_ms: int | None = None

    def record(self, *, seq: Seq32, send_time_ms: int) -> None:
        """
        Record a fresh in-flight RTT sample at the supplied seq
        and send_time_ms. Caller is responsible for the §4
        'one sample per RTT' gate (only call when 'seq is None').

        Reference: RFC 6298 §4 (RTT sample collection).
        """

        self.seq = seq
        self.send_time_ms = send_time_ms
        self.retransmitted = False

    def clear(self) -> None:
        """
        Clear the in-flight sample tracker so the next outbound
        sequence-consuming segment can record a fresh one.
        Called from the harvest path in '_phase3_harvest_rtt_samples'
        once the covering ACK has been observed.

        Reference: RFC 6298 §4 (sample turnover).
        """

        self.seq = None
        self.send_time_ms = None
        self.retransmitted = False

    def taint(self) -> None:
        """
        Set the §3 Karn flag True. Called from the retransmit
        path when the in-flight sampled seq is sent again; the
        eventual harvest skips the rto_state update for this
        sample so the estimator is not poisoned by a sample
        that could correspond to either the original or the
        retransmission.

        Reference: RFC 6298 §3 (Karn's algorithm).
        """

        self.retransmitted = True
