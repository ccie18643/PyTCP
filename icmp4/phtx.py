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
# icmp4/phtx.py - packet handler for outbound ICMPv4 packets
#


from typing import Optional

import config
import icmp4.fpa
from misc.ipv4_address import IPv4Address
from misc.ipv6_address import IPv6Address
from misc.tracker import Tracker


def _phtx_icmp4(
    self,
    ip4_src: IPv4Address,
    ip4_dst: IPv6Address,
    icmp4_type: int,
    icmp4_code: int = 0,
    icmp4_ec_id: Optional[int] = None,
    icmp4_ec_seq: Optional[int] = None,
    icmp4_ec_data: Optional[bytes] = None,
    icmp4_un_data: Optional[bytes] = None,
    echo_tracker: Optional[Tracker] = None,
) -> None:
    """Handle outbound ICMPv4 packets"""

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not config.ip4_support:
        return

    icmp4_packet_tx = icmp4.fpa.Assembler(
        type=icmp4_type,
        code=icmp4_code,
        ec_id=icmp4_ec_id,
        ec_seq=icmp4_ec_seq,
        ec_data=icmp4_ec_data,
        un_data=icmp4_un_data,
        echo_tracker=echo_tracker,
    )

    if __debug__:
        self._logger.opt(ansi=True).info(f"<magenta>{icmp4_packet_tx.tracker}</magenta> - {icmp4_packet_tx}")
    self._phtx_ip4(ip4_src=ip4_src, ip4_dst=ip4_dst, carried_packet=icmp4_packet_tx)
