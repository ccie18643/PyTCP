#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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


# pylint: disable = expression-not-assigned
# pylint: disable = too-many-locals
# pylint: disable = too-many-branches
# pylint: disable = protected-access

"""
Module contains packet handler for the outbound TCP packets.

pytcp/protocols/tcp/phtx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.tcp.fpa import (
    TcpAssembler,
    TcpOptEol,
    TcpOptMss,
    TcpOptNop,
    TcpOptSackPerm,
    TcpOptTimestamp,
    TcpOptWscale,
)

if TYPE_CHECKING:
    from pytcp.lib.ip_address import IpAddress
    from pytcp.subsystems.packet_handler import PacketHandler


def _phtx_tcp(
    self: PacketHandler,
    *,
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
    tcp_mss: int | None = None,
    tcp_wscale: int | None = None,
    tcp_win: int = 0,
    tcp_urp: int = 0,
    tcp_data: bytes | None = None,
    echo_tracker: Tracker | None = None,
) -> TxStatus:
    """
    Handle outbound TCP packets.
    """

    self.packet_stats_tx.tcp__pre_assemble += 1

    tcp_options: list[
        TcpOptMss
        | TcpOptWscale
        | TcpOptSackPerm
        | TcpOptTimestamp
        | TcpOptEol
        | TcpOptNop
    ] = []

    if tcp_mss:
        self.packet_stats_tx.tcp__opt_mss += 1
        tcp_options.append(TcpOptMss(tcp_mss))

    if tcp_wscale:
        self.packet_stats_tx.tcp__opt_nop += 1
        self.packet_stats_tx.tcp__opt_wscale += 1
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

    if tcp_flag_ns:
        self.packet_stats_tx.tcp__flag_ns += 1

    if tcp_flag_crw:
        self.packet_stats_tx.tcp__flag_crw += 1

    if tcp_flag_ece:
        self.packet_stats_tx.tcp__flag_ece += 1

    if tcp_flag_urg:
        self.packet_stats_tx.tcp__flag_urg += 1

    if tcp_flag_ack:
        self.packet_stats_tx.tcp__flag_ack += 1

    if tcp_flag_psh:
        self.packet_stats_tx.tcp__flag_psh += 1

    if tcp_flag_rst:
        self.packet_stats_tx.tcp__flag_rst += 1

    if tcp_flag_syn:
        self.packet_stats_tx.tcp__flag_syn += 1

    if tcp_flag_fin:
        self.packet_stats_tx.tcp__flag_fin += 1

    __debug__ and log("tcp", f"{tcp_packet_tx.tracker} - {tcp_packet_tx}")

    if ip_src.is_ip6 and ip_dst.is_ip6:
        self.packet_stats_tx.tcp__send += 1
        return self._phtx_ip6(
            ip6_src=cast(Ip6Address, ip_src),
            ip6_dst=cast(Ip6Address, ip_dst),
            carried_packet=tcp_packet_tx,
        )

    if ip_src.is_ip4 and ip_dst.is_ip4:
        self.packet_stats_tx.tcp__send += 1
        return self._phtx_ip4(
            ip4_src=cast(Ip4Address, ip_src),
            ip4_dst=cast(Ip4Address, ip_dst),
            carried_packet=tcp_packet_tx,
        )

    self.packet_stats_tx.tcp__unknown__drop += 1
    return TxStatus.DROPED__TCP__UNKNOWN
