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
This module contains the 'TcpStatus' read-only snapshot returned
by 'TcpSocket.status()' per RFC 9293 §3.9.1 STATUS user/TCP
interface call.

pytcp/runtime/socket/tcp__status.py

ver 3.0.9
"""

from dataclasses import dataclass

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__enums import FsmState


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpStatus:
    """
    Read-only snapshot of a TCP connection's user-visible state
    per RFC 9293 §3.9.1 STATUS.
    """

    state: FsmState
    local_address: Ip4Address | Ip6Address
    local_port: int
    remote_address: Ip4Address | Ip6Address
    remote_port: int
    snd_una: int
    snd_nxt: int
    snd_wnd: int
    rcv_nxt: int
    rcv_wnd: int
    snd_mss: int
    rcv_mss: int
    snd_wsc: int
    rcv_wsc: int
    tx_buffer_len: int
    rx_buffer_len: int
