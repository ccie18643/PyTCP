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
This module contains the per-session receiver-side RTT estimator state
container. Unlike the RFC 6298 sender SRTT (which needs our data to be
acked), this is fed from the RFC 7323 TSecr echo on inbound data
segments, so it produces an RTT measurement even on a pure receiver
that only sends ACKs — the round-trip cadence the Tier-3 receive-buffer
Dynamic Right-Sizing (Track R) gate depends on (Linux 'rcv_rtt_est' /
'tcp_rcv_rtt_measure_ts').

pytcp/protocols/tcp/state/tcp__state__rcv_rtt.py

ver 3.0.9
"""

from dataclasses import dataclass


@dataclass(slots=True)
class RcvRttState:
    """
    Per-session receiver-side RTT estimator. Owned by 'TcpSession';
    written on the RX/ACK thread from the inbound-data TSecr echo and
    read by the DRS measurement (app thread). Timestamps-gated: only
    fed while bilateral RFC 7323 TSopt is active.
    """

    # Smoothed receiver RTT (ms), 'None' until the first sample —
    # DRS treats 'None' as "no cadence yet" and skips its adjust.
    rtt_ms: int | None = None

    # The most recently sampled TSecr. A segment echoing the same
    # TSecr is a within-RTT duplicate and contributes no new sample,
    # so a burst does not overweight the estimate (Linux dedups on
    # 'rcv_rtt_last_tsecr').
    last_tsecr: int | None = None

    # No-timestamps fallback anchor (Linux 'rcv_rtt_est'). When TSopt
    # is not active, RTT is measured as the wall-time to receive one
    # advertised window of data: 'fallback_seq' is 'rcv_nxt + rcv_wnd'
    # at the anchor, 'fallback_time_ms' the anchor time, and
    # 'fallback_active' guards the "no anchor yet" state.
    fallback_seq: int = 0
    fallback_time_ms: int = 0
    fallback_active: bool = False

    def observe(self, *, sample_ms: int, tsecr: int) -> None:
        """
        Fold a receiver RTT sample ('now_ms - TSecr') into the
        smoothed estimate. Deduplicated on 'tsecr' so at most one
        sample lands per round trip. The first sample seeds the
        estimate directly; subsequent samples fold via the
        alpha = 1/8 EWMA '(7 * old + sample) // 8' (the RFC 6298 SRTT
        smoothing, matching Linux 'tcp_rcv_rtt_update' win_dep=0).
        """

        if tsecr == self.last_tsecr:
            return
        self.last_tsecr = tsecr
        if self.rtt_ms is None:
            self.rtt_ms = sample_ms
        else:
            self.rtt_ms = (7 * self.rtt_ms + sample_ms) // 8

    def observe_window(self, *, sample_ms: int) -> None:
        """
        Fold a no-timestamps window-based RTT sample. The window-time
        measure biases high (delayed ACKs, application stalls), so —
        like Linux 'tcp_rcv_rtt_update' with win_dep=1 — it takes the
        minimum rather than an EWMA: the first sample seeds the
        estimate, later samples lower it toward the true RTT but never
        raise it.
        """

        if self.rtt_ms is None or sample_ms < self.rtt_ms:
            self.rtt_ms = sample_ms
