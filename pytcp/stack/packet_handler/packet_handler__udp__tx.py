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
This module contains protocol support for the outbound UDP packets.

pytcp/subsystems/packet_handler/packet_handler__udp__tx.py

ver 3.0.4
"""


from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, Ip6Address
from net_proto import Tracker, UdpAssembler

from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus


class PacketHandlerUdpTx(ABC):
    """
    Class implements packet handler for the outbound UDP packets.
    """

    if TYPE_CHECKING:
        from net_addr import IpAddress
        from net_proto import (
            IP4__DEFAULT_TTL,
            IP6__DEFAULT_HOP_LIMIT,
            Icmp4Assembler,
            Icmp6Assembler,
            Ip4Payload,
            Ip6FragAssembler,
            Ip6Payload,
            RawAssembler,
        )

        from pytcp.lib.packet_stats import PacketStatsTx

        _packet_stats_tx: PacketStatsTx

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

    def _phtx_udp(
        self,
        *,
        ip__src: Ip6Address | Ip4Address,
        ip__dst: Ip6Address | Ip4Address,
        udp__sport: int,
        udp__dport: int,
        udp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound UDP packets.
        """

        self._packet_stats_tx.inc("udp__pre_assemble")

        udp_packet_tx = UdpAssembler(
            udp__sport=udp__sport,
            udp__dport=udp__dport,
            udp__payload=udp__payload,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("udp", f"{udp_packet_tx.tracker} - {udp_packet_tx}")

        match ip__src.is_ip6, ip__dst.is_ip6, ip__src.is_ip4, ip__dst.is_ip4:
            case True, True, False, False:
                self._packet_stats_tx.inc("udp__send")
                return self._phtx_ip6(
                    ip6__src=cast(Ip6Address, ip__src),
                    ip6__dst=cast(Ip6Address, ip__dst),
                    ip6__payload=udp_packet_tx,
                )
            case False, False, True, True:
                self._packet_stats_tx.inc("udp__send")
                return self._phtx_ip4(
                    ip4__src=cast(Ip4Address, ip__src),
                    ip4__dst=cast(Ip4Address, ip__dst),
                    ip4__payload=udp_packet_tx,
                )
            case _:
                raise ValueError(
                    f"Invalid IP address version combination: {ip__src} -> {ip__dst}"
                )

    def send_udp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        udp__local_port: int,
        udp__remote_port: int,
        udp__payload: bytes = bytes(),
    ) -> TxStatus:
        """
        Interface method for UDP Socket -> Packet Assembler communication.
        """

        return self._phtx_udp(
            ip__src=ip__local_address,
            ip__dst=ip__remote_address,
            udp__sport=udp__local_port,
            udp__dport=udp__remote_port,
            udp__payload=udp__payload,
        )
