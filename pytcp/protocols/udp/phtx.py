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
# protocols/udp/phtx.py - protocol support for outbound UDP packets
#


from __future__ import annotations

from typing import TYPE_CHECKING

from lib.logger import log
from lib.tracker import Tracker
from misc.tx_status import TxStatus
from protocols.udp.fpa import UdpAssembler

if TYPE_CHECKING:
    from lib.ip_address import IpAddress


def _phtx_udp(
    self,
    *,
    ip_src: IpAddress,
    ip_dst: IpAddress,
    udp_sport: int,
    udp_dport: int,
    udp_data: bytes | None = None,
    echo_tracker: Tracker | None = None,
) -> TxStatus:
    """Handle outbound UDP packets"""

    self.packet_stats_tx.udp__pre_assemble += 1

    assert 0 < udp_sport < 65536, f"{udp_sport=}"
    assert 0 < udp_dport < 65536, f"{udp_dport=}"

    udp_packet_tx = UdpAssembler(sport=udp_sport, dport=udp_dport, data=udp_data, echo_tracker=echo_tracker)

    if __debug__:
        log("udp", f"{udp_packet_tx.tracker} - {udp_packet_tx}")

    if ip_src.is_ip6 and ip_dst.is_ip6:
        self.packet_stats_tx.udp__send += 1
        return self._phtx_ip6(ip6_src=ip_src, ip6_dst=ip_dst, carried_packet=udp_packet_tx)

    if ip_src.is_ip4 and ip_dst.is_ip4:
        self.packet_stats_tx.udp__send += 1
        return self._phtx_ip4(ip4_src=ip_src, ip4_dst=ip_dst, carried_packet=udp_packet_tx)

    self.packet_stats_tx.udp__unknown__drop += 1
    return TxStatus.DROPED__UDP__UNKNOWN
