#!/usr/bin/env python3

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
Module contains packet handler for the outbound TCP packets.

pytcp/subsystems/packet_handler/packet_handler__tcp__tx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.tcp.options.tcp_option__mss import TcpOptionMss
from pytcp.protocols.tcp.options.tcp_option__nop import TcpOptionNop
from pytcp.protocols.tcp.options.tcp_option__wscale import TcpOptionWscale
from pytcp.protocols.tcp.options.tcp_options import TcpOptions
from pytcp.protocols.tcp.tcp__assembler import TcpAssembler


class PacketHandlerTcpTx(ABC):
    """
    Class implements packet handler for the outbound TCP packets.
    """

    if TYPE_CHECKING:
        from net_addr import IpAddress
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.defaults import (
            IP4__DEFAULT_TTL,
            IP6__DEFAULT_HOP_LIMIT,
        )
        from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
        from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
        from pytcp.protocols.ip4.ip4__assembler import Ip4Payload
        from pytcp.protocols.ip6.ip6__assembler import Ip6Payload
        from pytcp.protocols.ip6_frag.ip6_frag__assembler import (
            Ip6FragAssembler,
        )
        from pytcp.protocols.raw.raw__assembler import RawAssembler

        packet_stats_tx: PacketStatsTx

        # pylint: disable=unused-argument

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int = IP6__DEFAULT_HOP_LIMIT,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus: ...

        def _phtx_ip4(
            self,
            *,
            ip4__dst: Ip4Address,
            ip4__src: Ip4Address,
            ip4__ttl: int = IP4__DEFAULT_TTL,
            ip4__payload: Ip4Payload = RawAssembler(),
        ) -> TxStatus: ...

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
        tcp__flag_cwr: bool = False,
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
        tcp__urg: int = 0,
        tcp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound TCP packets.
        """

        self.packet_stats_tx.tcp__pre_assemble += 1

        # TODO: This code does not seem to be correct,
        # need to ba able to stack options.

        options = TcpOptions()

        if tcp__mss:
            self.packet_stats_tx.tcp__opt_mss += 1
            options = TcpOptions(TcpOptionMss(mss=tcp__mss))

        if tcp__wscale:
            self.packet_stats_tx.tcp__opt_nop += 1
            self.packet_stats_tx.tcp__opt_wscale += 1
            options = TcpOptions(
                TcpOptionNop(),
                TcpOptionWscale(wscale=tcp__wscale),
            )

        tcp_packet_tx = TcpAssembler(
            tcp__sport=tcp__sport,
            tcp__dport=tcp__dport,
            tcp__seq=tcp__seq,
            tcp__ack=tcp__ack,
            tcp__flag_ns=tcp__flag_ns,
            tcp__flag_cwr=tcp__flag_cwr,
            tcp__flag_ece=tcp__flag_ece,
            tcp__flag_urg=tcp__flag_urg,
            tcp__flag_ack=tcp__flag_ack,
            tcp__flag_psh=tcp__flag_psh,
            tcp__flag_rst=tcp__flag_rst,
            tcp__flag_syn=tcp__flag_syn,
            tcp__flag_fin=tcp__flag_fin,
            tcp__win=tcp__win,
            tcp__urg=tcp__urg,
            tcp__options=options,
            tcp__payload=tcp__payload,
            echo_tracker=echo_tracker,
        )

        if tcp__flag_ns:
            self.packet_stats_tx.tcp__flag_ns += 1

        if tcp__flag_cwr:
            self.packet_stats_tx.tcp__flag_cwr += 1

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

        match ip__src.is_ip6, ip__dst.is_ip6, ip__src.is_ip4, ip__dst.is_ip4:
            case True, True, False, False:
                self.packet_stats_tx.tcp__send += 1
                return self._phtx_ip6(
                    ip6__src=cast(Ip6Address, ip__src),
                    ip6__dst=cast(Ip6Address, ip__dst),
                    ip6__payload=tcp_packet_tx,
                )
            case False, False, True, True:
                self.packet_stats_tx.tcp__send += 1
                return self._phtx_ip4(
                    ip4__src=cast(Ip4Address, ip__src),
                    ip4__dst=cast(Ip4Address, ip__dst),
                    ip4__payload=tcp_packet_tx,
                )
            case _:
                raise ValueError(
                    f"Invalid IP address version combination: {ip__src} -> {ip__dst}"
                )

    def send_tcp_packet(
        self,
        *,
        ip__local_address: IpAddress,
        ip__remote_address: IpAddress,
        tcp__local_port: int,
        tcp__remote_port: int,
        tcp__flag_syn: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_fin: bool = False,
        tcp__flag_rst: bool = False,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__win: int = 0,
        tcp__wscale: int | None = None,
        tcp__mss: int | None = None,
        tcp__payload: bytes = bytes(),
    ) -> TxStatus:
        """
        Interface method for TCP Socket -> FPA communication.
        """

        return self._phtx_tcp(
            ip__src=ip__local_address,
            ip__dst=ip__remote_address,
            tcp__sport=tcp__local_port,
            tcp__dport=tcp__remote_port,
            tcp__flag_syn=tcp__flag_syn,
            tcp__flag_ack=tcp__flag_ack,
            tcp__flag_fin=tcp__flag_fin,
            tcp__flag_rst=tcp__flag_rst,
            tcp__seq=tcp__seq,
            tcp__ack=tcp__ack,
            tcp__win=tcp__win,
            tcp__wscale=tcp__wscale,
            tcp__mss=tcp__mss,
            tcp__payload=tcp__payload,
        )
