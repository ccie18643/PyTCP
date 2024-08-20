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

# pylint: disable=expression-not-assigned
# pylint: disable=unused-argument


"""
Module contains protocol support for the outbound UDP packets.

pytcp/protocols/udp/udp__packet_handler_tx.py

ver 3.0.0
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, cast

from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.udp.udp__assembler import UdpAssembler


class UdpPacketHandlerTx(ABC):
    """
    Class implements packet handler for the outbound TCP packets.
    """

    if TYPE_CHECKING:
        from pytcp.config import IP4__DEFAULT_TTL, IP6__DEFAULT_HOP_LIMIT
        from pytcp.lib.ip_address import IpAddress
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
        from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
        from pytcp.protocols.ip4.ip4__assembler import Ip4Payload
        from pytcp.protocols.ip6.ip6__assembler import Ip6Payload
        from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__assembler import (
            Ip6ExtFragAssembler,
        )
        from pytcp.protocols.raw.raw__assembler import RawAssembler

        packet_stats_tx: PacketStatsTx

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
        ip__src: IpAddress,
        ip__dst: IpAddress,
        udp__sport: int,
        udp__dport: int,
        udp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound UDP packets.
        """

        self.packet_stats_tx.udp__pre_assemble += 1

        udp_packet_tx = UdpAssembler(
            udp__sport=udp__sport,
            udp__dport=udp__dport,
            udp__payload=udp__payload,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("udp", f"{udp_packet_tx.tracker} - {udp_packet_tx}")

        if ip__src.is_ip6 and ip__dst.is_ip6:
            self.packet_stats_tx.udp__send += 1
            return self._phtx_ip6(
                ip6__src=cast(Ip6Address, ip__src),
                ip6__dst=cast(Ip6Address, ip__dst),
                ip6__payload=udp_packet_tx,
            )

        if ip__src.is_ip4 and ip__dst.is_ip4:
            self.packet_stats_tx.udp__send += 1
            return self._phtx_ip4(
                ip4__src=cast(Ip4Address, ip__src),
                ip4__dst=cast(Ip4Address, ip__dst),
                ip4__payload=udp_packet_tx,
            )

        self.packet_stats_tx.udp__unknown__drop += 1
        return TxStatus.DROPED__UDP__UNKNOWN

    def send_udp_packet(
        self,
        *,
        ip__local_address: IpAddress,
        ip__remote_address: IpAddress,
        udp__local_port: int,
        udp__remote_port: int,
        udp__payload: bytes = bytes(),
    ) -> TxStatus:
        """
        Interface method for UDP Socket -> FPA communication.
        """

        return self._phtx_udp(
            ip__src=ip__local_address,
            ip__dst=ip__remote_address,
            udp__sport=udp__local_port,
            udp__dport=udp__remote_port,
            udp__payload=udp__payload,
        )
