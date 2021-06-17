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


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Optional

from lib.ip4_address import Ip4Address
from lib.ip6_address import Ip6Address
from lib.logger import log
from lib.tracker import Tracker
from misc.tx_status import TxStatus
from protocols.udp.fpa import UdpAssembler

if TYPE_CHECKING:
    from lib.ip_address import IpAddress


def _phtx_udp(
    self,
    ip_src: IpAddress,
    ip_dst: IpAddress,
    udp_sport: int,
    udp_dport: int,
    udp_data: Optional[bytes] = None,
    echo_tracker: Optional[Tracker] = None,
) -> TxStatus:
    """Handle outbound UDP packets"""

    assert 0 < udp_sport < 65536, f"{udp_sport=}"
    assert 0 < udp_dport < 65536, f"{udp_dport=}"

    udp_packet_tx = UdpAssembler(sport=udp_sport, dport=udp_dport, data=udp_data, echo_tracker=echo_tracker)

    if __debug__:
        log("udp", f"{udp_packet_tx.tracker} - {udp_packet_tx}")

    if isinstance(ip_src, Ip6Address) and isinstance(ip_dst, Ip6Address):
        return self._phtx_ip6(ip6_src=ip_src, ip6_dst=ip_dst, carried_packet=udp_packet_tx)

    if isinstance(ip_src, Ip4Address) and isinstance(ip_dst, Ip4Address):
        return self._phtx_ip4(ip4_src=ip_src, ip4_dst=ip_dst, carried_packet=udp_packet_tx)

    return TxStatus.DROPED_UDP_UNKNOWN
