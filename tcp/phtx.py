#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tcp/phtx.py - packet handler for outbound TCP packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Optional

from lib.ip4_address import Ip4Address
from lib.ip6_address import Ip6Address
from lib.logger import log
from lib.tracker import Tracker
from misc.tx_status import TxStatus
from tcp.fpa import (
    TcpAssembler,
    TcpOptEol,
    TcpOptMss,
    TcpOptNop,
    TcpOptSackPerm,
    TcpOptTimestamp,
    TcpOptWscale,
)

if TYPE_CHECKING:
    from lib.ip_address import IpAddress


def _phtx_tcp(
    self,
    ip_src: IpAddress,
    ip_dst: IpAddress,
    tcp_sport: int,
    tcp_dport: int,
    tcp_seq: int = 0,
    tcp_ack: int = 0,
    tcp_flag_ns: bool = False,
    tcp_flag_crw: bool = False,
    tcp_flag_ece: bool = False,
    tcp_flag_urg: bool = False,
    tcp_flag_ack: bool = False,
    tcp_flag_psh: bool = False,
    tcp_flag_rst: bool = False,
    tcp_flag_syn: bool = False,
    tcp_flag_fin: bool = False,
    tcp_mss: Optional[int] = None,
    tcp_wscale: Optional[int] = None,
    tcp_win: int = 0,
    tcp_urp: int = 0,
    tcp_data: Optional[bytes] = None,
    echo_tracker: Optional[Tracker] = None,
) -> TxStatus:
    """Handle outbound TCP packets"""

    assert 0 < tcp_sport < 65536
    assert 0 < tcp_dport < 65536

    tcp_options: list[TcpOptMss | TcpOptWscale | TcpOptSackPerm | TcpOptTimestamp | TcpOptEol | TcpOptNop] = []

    if tcp_mss:
        tcp_options.append(TcpOptMss(tcp_mss))

    if tcp_wscale:
        tcp_options.append(TcpOptNop())
        tcp_options.append(TcpOptWscale(tcp_wscale))

    tcp_packet_tx = TcpAssembler(
        sport=tcp_sport,
        dport=tcp_dport,
        seq=tcp_seq,
        ack=tcp_ack,
        flag_ns=tcp_flag_ns,
        flag_crw=tcp_flag_crw,
        flag_ece=tcp_flag_ece,
        flag_urg=tcp_flag_urg,
        flag_ack=tcp_flag_ack,
        flag_psh=tcp_flag_psh,
        flag_rst=tcp_flag_rst,
        flag_syn=tcp_flag_syn,
        flag_fin=tcp_flag_fin,
        win=tcp_win,
        urp=tcp_urp,
        options=tcp_options,
        data=tcp_data,
        echo_tracker=echo_tracker,
    )

    log("tcp", f"{tcp_packet_tx.tracker} - <INFO>{tcp_packet_tx}</>")

    if isinstance(ip_src, Ip6Address) and isinstance(ip_dst, Ip6Address):
        return self._phtx_ip6(ip6_src=ip_src, ip6_dst=ip_dst, carried_packet=tcp_packet_tx)

    if isinstance(ip_src, Ip4Address) and isinstance(ip_dst, Ip4Address):
        return self._phtx_ip4(ip4_src=ip_src, ip4_dst=ip_dst, carried_packet=tcp_packet_tx)

    return TxStatus.DROPED_TCP_UNKNOWN
