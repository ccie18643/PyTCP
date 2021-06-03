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
# udp/phtx.py - protocol support for outbound UDP packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Union

import config
from misc.tracker import Tracker
from udp.fpa import UdpAssembler

if TYPE_CHECKING:
    from lib.ip4_address import Ip4Address
    from lib.ip6_address import Ip6Address


def _phtx_udp(
    self,
    ip_src: Union[Ip6Address, Ip4Address],
    ip_dst: Union[Ip6Address, Ip4Address],
    udp_sport: int,
    udp_dport: int,
    udp_data: bytes = b"",
    echo_tracker: Tracker = None,
) -> None:
    """Handle outbound UDP packets"""

    assert 0 < udp_sport < 65536
    assert 0 < udp_dport < 65536

    # Check if IPv4 protocol support is enabled, if not then silently drop the IPv4 packet
    if not config.ip4_support and ip_dst.version == 4:
        return

    # Check if IPv6 protocol support is enabled, if not then silently drop the IPv6 packet
    if not config.ip6_support and ip_dst.version == 6:
        return

    udp_packet_tx = UdpAssembler(sport=udp_sport, dport=udp_dport, data=udp_data, echo_tracker=echo_tracker)

    if __debug__:
        self._logger.opt(ansi=True).info(f"<magenta>{udp_packet_tx.tracker}</magenta> - {udp_packet_tx}")

    if ip_src.version == 6 and ip_dst.version == 6:
        self._phtx_ip6(ip6_src=ip_src, ip6_dst=ip_dst, carried_packet=udp_packet_tx)

    if ip_src.version == 4 and ip_dst.version == 4:
        self._phtx_ip4(ip4_src=ip_src, ip4_dst=ip_dst, carried_packet=udp_packet_tx)
