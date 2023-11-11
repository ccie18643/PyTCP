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

from abc import ABC
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


class PacketHandlerTxTcp(ABC):
    """
    Class implements packet handler for the outbound TCP packets.
    """

    if TYPE_CHECKING:
        from pytcp.config import IP4_DEFAULT_TTL, IP6_DEFAULT_HOP
        from pytcp.lib.ip_address import IpAddress
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.icmp4.fpa import Icmp4Assembler
        from pytcp.protocols.icmp6.fpa import Icmp6Assembler
        from pytcp.protocols.ip4.ps import Ip4Payload
        from pytcp.protocols.ip6.ps import Ip6Payload
        from pytcp.protocols.ip6_ext_frag.fpa import Ip6ExtFragAssembler
        from pytcp.protocols.raw.fpa import RawAssembler
        from pytcp.protocols.udp.fpa import UdpAssembler

        packet_stats_tx: PacketStatsTx

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int = IP6_DEFAULT_HOP,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus:
            ...

        def _phtx_ip4(
            self,
            *,
            ip4__dst: Ip4Address,
            ip4__src: Ip4Address,
            ip4__ttl: int = IP4_DEFAULT_TTL,
            ip4__payload: Ip4Payload = RawAssembler(),
        ) -> TxStatus:
            ...

    def _phtx_tcp(
        self,
        *,
        ip__src: IpAddress,
        ip__dst: IpAddress,
        tcp__sport: int,
        tcp__dport: int,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__flag_ns: bool = False,
        tcp__flag_crw: bool = False,
        tcp__flag_ece: bool = False,
        tcp__flag_urg: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_psh: bool = False,
        tcp__flag_rst: bool = False,
        tcp__flag_syn: bool = False,
        tcp__flag_fin: bool = False,
        tcp__mss: int | None = None,
        tcp__wscale: int | None = None,
        tcp__win: int = 0,
        tcp__urp: int = 0,
        tcp__data: bytes | None = None,
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

        if tcp__mss:
            self.packet_stats_tx.tcp__opt_mss += 1
            tcp_options.append(TcpOptMss(tcp__mss))

        if tcp__wscale:
            self.packet_stats_tx.tcp__opt_nop += 1
            self.packet_stats_tx.tcp__opt_wscale += 1
            tcp_options.append(TcpOptNop())
            tcp_options.append(TcpOptWscale(tcp__wscale))

        tcp_packet_tx = TcpAssembler(
            sport=tcp__sport,
            dport=tcp__dport,
            seq=tcp__seq,
            ack=tcp__ack,
            flag_ns=tcp__flag_ns,
            flag_crw=tcp__flag_crw,
            flag_ece=tcp__flag_ece,
            flag_urg=tcp__flag_urg,
            flag_ack=tcp__flag_ack,
            flag_psh=tcp__flag_psh,
            flag_rst=tcp__flag_rst,
            flag_syn=tcp__flag_syn,
            flag_fin=tcp__flag_fin,
            win=tcp__win,
            urp=tcp__urp,
            options=tcp_options,
            data=tcp__data,
            echo_tracker=echo_tracker,
        )

        if tcp__flag_ns:
            self.packet_stats_tx.tcp__flag_ns += 1

        if tcp__flag_crw:
            self.packet_stats_tx.tcp__flag_crw += 1

        if tcp__flag_ece:
            self.packet_stats_tx.tcp__flag_ece += 1

        if tcp__flag_urg:
            self.packet_stats_tx.tcp__flag_urg += 1

        if tcp__flag_ack:
            self.packet_stats_tx.tcp__flag_ack += 1

        if tcp__flag_psh:
            self.packet_stats_tx.tcp__flag_psh += 1

        if tcp__flag_rst:
            self.packet_stats_tx.tcp__flag_rst += 1

        if tcp__flag_syn:
            self.packet_stats_tx.tcp__flag_syn += 1

        if tcp__flag_fin:
            self.packet_stats_tx.tcp__flag_fin += 1

        __debug__ and log("tcp", f"{tcp_packet_tx.tracker} - {tcp_packet_tx}")

        if ip__src.is_ip6 and ip__dst.is_ip6:
            self.packet_stats_tx.tcp__send += 1
            return self._phtx_ip6(
                ip6__src=cast(Ip6Address, ip__src),
                ip6__dst=cast(Ip6Address, ip__dst),
                ip6__payload=tcp_packet_tx,
            )

        if ip__src.is_ip4 and ip__dst.is_ip4:
            self.packet_stats_tx.tcp__send += 1
            return self._phtx_ip4(
                ip4__src=cast(Ip4Address, ip__src),
                ip4__dst=cast(Ip4Address, ip__dst),
                ip4__payload=tcp_packet_tx,
            )

        self.packet_stats_tx.tcp__unknown__drop += 1
        return TxStatus.DROPED__TCP__UNKNOWN
