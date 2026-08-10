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
This module contains the immutable TCP_INFO snapshot dataclass.

'TcpInfoSnapshot' is the read-only, copy-by-value introspection
surface 'TcpSession.tcp_info()' returns. It carries exactly the
scalars the Linux-shaped 'struct tcp_info' packer
('pytcp/runtime/socket/tcp__info.py') needs, so the packer never
reaches into the session's private collaborator objects. Per the
CLAUDE.md Phase-3 design implications, state introspection is
read-only and copy-by-value; the snapshot is a frozen dataclass
taken under the session's own accessors, never a live reference.

pytcp/protocols/tcp/session/tcp__session__info.py

ver 3.0.9
"""

from dataclasses import dataclass

from pytcp.protocols.tcp.tcp__enums import CcMode, FsmState


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpInfoSnapshot:
    """
    Read-only, copy-by-value snapshot of the per-session scalars
    the Linux 'struct tcp_info' packer needs.
    """

    state: FsmState
    cc_mode: CcMode
    retransmit_count: int
    send_ts: bool
    send_sack: bool
    snd_wsc: int
    rcv_wsc: int
    ecn_enabled: bool
    accecn_enabled: bool
    rto_ms: int
    srtt_ms: int | None
    rttvar_ms: int | None
    snd_mss: int
    rcv_mss: int
    snd_una: int
    snd_nxt: int
    snd_wnd: int
    rcv_wnd_max: int
    cwnd: int
    ssthresh: int
    pmtu: int
    tx_buffer_len: int
    dsack_received: int
