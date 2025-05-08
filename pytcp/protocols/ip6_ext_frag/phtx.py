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
# pylint: disable = protected-access

"""
Module contains packet handler for the outbound IPv6 fragment extension header.

pytcp/protocols/ip6_ext_frag/phtx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.ip6.ps import IP6_HEADER_LEN
from pytcp.protocols.ip6_ext_frag.fpa import Ip6ExtFragAssembler
from pytcp.protocols.ip6_ext_frag.ps import IP6_EXT_FRAG_HEADER_LEN

if TYPE_CHECKING:
    from pytcp.protocols.ip6.fpa import Ip6Assembler
    from pytcp.subsystems.packet_handler import PacketHandler


def _phtx_ip6_ext_frag(
    self: PacketHandler, *, ip6_packet_tx: Ip6Assembler
) -> TxStatus:
    """
    Handle outbound IPv6 fragment extension header.
    """

    self.packet_stats_tx.ip6_ext_frag__pre_assemble += 1

    data = memoryview(bytearray(ip6_packet_tx.dlen))
    ip6_packet_tx._carried_packet.assemble(data, ip6_packet_tx.pshdr_sum)
    data_mtu = (
        config.TAP_MTU - IP6_HEADER_LEN - IP6_EXT_FRAG_HEADER_LEN
    ) & 0b1111111111111000
    data_frags = [data[_ : data_mtu + _] for _ in range(0, len(data), data_mtu)]
    offset = 0
    self.ip6_id += 1
    ip6_tx_status: set[TxStatus] = set()
    for data_frag in data_frags:
        ip6_ext_frag_tx = Ip6ExtFragAssembler(
            next=ip6_packet_tx.next,
            offset=offset,
            flag_mf=data_frag is not data_frags[-1],
            id=self.ip6_id,
            data=data_frag,
        )
        __debug__ and log(
            "ip6", f"{ip6_ext_frag_tx.tracker} - {ip6_ext_frag_tx}"
        )
        offset += len(data_frag)
        self.packet_stats_tx.ip6_ext_frag__send += 1
        ip6_tx_status.add(
            self._phtx_ip6(
                ip6_src=ip6_packet_tx.src,
                ip6_dst=ip6_packet_tx.dst,
                carried_packet=ip6_ext_frag_tx,
            )
        )

    # Return the most severe code
    for tx_status in [
        TxStatus.DROPED__ETHER__DST_RESOLUTION_FAIL,
        TxStatus.DROPED__ETHER__DST_NO_GATEWAY_IP6,
        TxStatus.DROPED__ETHER__DST_ND_CACHE_FAIL,
        TxStatus.DROPED__ETHER__DST_GATEWAY_ND_CACHE_FAIL,
        TxStatus.PASSED__ETHER__TO_TX_RING,
    ]:
        if tx_status in ip6_tx_status:
            return tx_status

    return TxStatus.DROPED__IP6__EXT_FRAG_UNKNOWN
