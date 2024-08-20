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
Module contains packet handler for the outbound IPv6 fragment extension header.

pytcp/protocols/ip6_ext_frag/ip6_ext_frag__packet_handler_tx.py

ver 3.0.0
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from pytcp.protocols.ip6.ip6__header import IP6__HEADER__LEN
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__assembler import (
    Ip6ExtFragAssembler,
)
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__header import (
    IP6_EXT_FRAG__HEADER__LEN,
)
from pytcp.protocols.tcp.tcp__assembler import TcpAssembler
from pytcp.protocols.udp.udp__assembler import UdpAssembler


class Ip6ExtFragPacketHandlerTx(ABC):
    """
    Packet handler for the outbound IPv6 fragment extension header.
    """

    if TYPE_CHECKING:
        from pytcp.lib.ip6_address import Ip6Address
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.ip6.ip6__assembler import Ip6Assembler, Ip6Payload
        from pytcp.protocols.raw.raw__assembler import RawAssembler

        packet_stats_tx: PacketStatsTx
        ip6_id: int

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int = config.IP6__DEFAULT_HOP_LIMIT,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus: ...

    def _phtx_ip6_ext_frag(self, *, ip6_packet_tx: Ip6Assembler) -> TxStatus:
        """
        Handle outbound IPv6 fagment extension header.
        """

        self.packet_stats_tx.ip6_ext_frag__pre_assemble += 1

        if isinstance(
            ip6_packet_tx.payload, (TcpAssembler, UdpAssembler, Icmp6Assembler)
        ):
            ip6_packet_tx.payload.pshdr_sum = ip6_packet_tx.pshdr_sum

        payload = bytearray(bytes(ip6_packet_tx.payload))

        payload_mtu = (
            config.INTERFACE__TAP__MTU
            - IP6__HEADER__LEN
            - IP6_EXT_FRAG__HEADER__LEN
        ) & 0b1111111111111000
        data_frags = [
            payload[_ : payload_mtu + _]
            for _ in range(0, len(payload), payload_mtu)
        ]
        offset = 0
        self.ip6_id += 1
        ip6_tx_status: set[TxStatus] = set()
        for data_frag in data_frags:
            ip6_ext_frag_tx = Ip6ExtFragAssembler(
                ip6_ext_frag__next=ip6_packet_tx.next,
                ip6_ext_frag__offset=offset,
                ip6_ext_frag__flag_mf=data_frag is not data_frags[-1],
                ip6_ext_frag__id=self.ip6_id,
                ip6_ext_frag__payload=data_frag,
            )
            __debug__ and log(
                "ip6", f"{ip6_ext_frag_tx.tracker} - {ip6_ext_frag_tx}"
            )
            offset += len(data_frag)
            self.packet_stats_tx.ip6_ext_frag__send += 1
            ip6_tx_status.add(
                self._phtx_ip6(
                    ip6__src=ip6_packet_tx.src,
                    ip6__dst=ip6_packet_tx.dst,
                    ip6__payload=ip6_ext_frag_tx,
                )
            )

        # Return the most severe code
        for tx_status in [
            TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL,
            TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP6,
            TxStatus.DROPED__ETHERNET__DST_ND_CACHE_FAIL,
            TxStatus.DROPED__ETHERNET__DST_GATEWAY_ND_CACHE_FAIL,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
        ]:
            if tx_status in ip6_tx_status:
                return tx_status

        return TxStatus.DROPED__IP6__EXT_FRAG_UNKNOWN
