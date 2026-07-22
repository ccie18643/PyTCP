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
This module contains the per-session window / MSS / WSCALE state
container, covering both the send-side (peer-told MSS, peer-
advertised window, peer WSCALE, RFC 5961 §5 MAX.SND.WND) and the
receive-side (our MSS, our WSCALE, our advertised-window cap).

pytcp/protocols/tcp/state/tcp__state__window.py

ver 3.0.8
"""

from dataclasses import dataclass

# RFC 7323 §2.3 maximum window-scale shift.
WINDOW_SCALE__MAX_SHIFT: int = 14

# The unscaled 16-bit advertised-window ceiling.
WINDOW__UNSCALED_MAX: int = 0xFFFF


def derive_rcv_wscale(space: int, /) -> int:
    """
    Compute the receive window-scale shift (RFC 7323 §2.2) needed to
    advertise 'space' bytes of receive window: the smallest shift for
    which 'WINDOW__UNSCALED_MAX << shift >= space', capped at the
    RFC 7323 §2.3 maximum of 14.

    Mirrors Linux 'tcp_select_initial_window', which sizes the shift
    from 'tcp_rmem[2]' (the DRS ceiling) rather than the initial
    window, so the negotiated scaling can express the whole buffer the
    receive window may auto-tune up to. The default 6 MiB 'tcp.rmem.max'
    yields shift 7 — the canonical Linux value.
    """

    shift = 0
    while shift < WINDOW_SCALE__MAX_SHIFT and (WINDOW__UNSCALED_MAX << shift) < space:
        shift += 1
    return shift


@dataclass(slots=True)
class WindowState:
    """
    Per-session window / MSS / WSCALE state. Owned by
    'TcpSession'; mutated at handshake (static fields anchored
    from peer's SYN options) and per-ACK (dynamic snd_wnd +
    max_window).
    """

    # RFC 9293 §3.7.1 peer-advertised maximum segment size.
    # 536 default per RFC 879 / 9293 §3.7.5; updated to peer's
    # MSS option value at SYN reception. Bounds the maximum
    # outbound TCP payload size.
    snd_mss: int = 536

    # RFC 9293 §3.8.4 peer-advertised receive window. Updated
    # to 'packet_rx_md.tcp__win << snd_wsc' on every accepted
    # ACK; drives the wire-level transmit gate together with
    # 'CcState.cwnd' (effective send window =
    # 'min(cwnd, snd_wnd)').
    snd_wnd: int = 0

    # RFC 7323 §2.3 peer-advertised window-scale shift. 0 by
    # default (unscaled); set to peer's WSCALE option value at
    # handshake completion if both sides advertised WSCALE.
    snd_wsc: int = 0

    # RFC 5961 §5 'MAX.SND.WND': running maximum of the peer's
    # advertised window. Used as the lower-bound tolerance for
    # ACK acceptability ('SND.UNA - MAX.SND.WND <= SEG.ACK <=
    # SND.NXT'); ACKs below this elicit a challenge ACK.
    max_window: int = 0

    # RFC 9293 §3.7.1 our maximum segment size. Computed from
    # the local interface MTU minus the IP+TCP header overhead;
    # advertised to peer in our SYN's MSS option.
    rcv_mss: int = 0

    # RFC 7323 §2.3 our window-scale shift. 7 by default
    # (canonical Linux value); zeroed if peer's SYN did not
    # advertise WSCALE per the §2.2 bilateral non-offer rule.
    rcv_wsc: int = 7

    # Maximum advertised receive window when the rx_buffer is
    # empty. The actual rcv_wnd value put on outbound segments
    # is 'rcv_wnd_max - len(rx_buffer)' (computed via the
    # property on TcpSession), so peer's flow-control loop
    # observes a window that shrinks as the application falls
    # behind on draining buffered data.
    rcv_wnd_max: int = 65535

    def bump_max_window(self, *, snd_wnd: int) -> None:
        """
        Advance MAX.SND.WND to 'snd_wnd' iff it is strictly
        greater than the current value. Called from
        '_phase5_consume_segment_and_postprocess' on every
        peer-advertised window update.

        Reference: RFC 5961 §5 (MAX.SND.WND running maximum).
        """

        if snd_wnd > self.max_window:
            self.max_window = snd_wnd
