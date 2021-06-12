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
# icmp6/phtx.py - packet handler for outbound ICMPv6 packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Optional, Union

import icmp6.fpa
from icmp6.fpa import Icmp6Assembler
from lib.logger import log
from lib.tracker import Tracker

if TYPE_CHECKING:
    from lib.ip6_address import Ip6Address
    from misc.tx_status import TxStatus


def _phtx_icmp6(
    self,
    ip6_src: Ip6Address,
    ip6_dst: Ip6Address,
    icmp6_type: int,
    icmp6_code: int = 0,
    ip6_hop: int = 64,
    icmp6_un_data: Optional[bytes] = None,
    icmp6_ec_id: Optional[int] = None,
    icmp6_ec_seq: Optional[int] = None,
    icmp6_ec_data: Optional[bytes] = None,
    icmp6_ns_target_address: Optional[Ip6Address] = None,
    icmp6_na_flag_r: bool = False,
    icmp6_na_flag_s: bool = False,
    icmp6_na_flag_o: bool = False,
    icmp6_na_target_address: Optional[Ip6Address] = None,
    icmp6_nd_options: Optional[list[Union[icmp6.fpa.Icmp6NdOptSLLA, icmp6.fpa.Icmp6NdOptTLLA, icmp6.fpa.Icmp6NdOptPI]]] = None,
    icmp6_mlr2_multicast_address_record=None,
    echo_tracker: Optional[Tracker] = None,
) -> TxStatus:
    """Handle outbound ICMPv6 packets"""

    icmp6_packet_tx = Icmp6Assembler(
        type=icmp6_type,
        code=icmp6_code,
        un_data=icmp6_un_data,
        ec_id=icmp6_ec_id,
        ec_seq=icmp6_ec_seq,
        ec_data=icmp6_ec_data,
        ns_target_address=icmp6_ns_target_address,
        na_flag_r=icmp6_na_flag_r,
        na_flag_s=icmp6_na_flag_s,
        na_flag_o=icmp6_na_flag_o,
        na_target_address=icmp6_na_target_address,
        nd_options=[] if icmp6_nd_options is None else icmp6_nd_options,
        mlr2_multicast_address_record=[] if icmp6_mlr2_multicast_address_record is None else icmp6_mlr2_multicast_address_record,
        echo_tracker=echo_tracker,
    )

    if __debug__:
        log("icmp6", f"{icmp6_packet_tx.tracker} - {icmp6_packet_tx}")

    return self._phtx_ip6(ip6_src=ip6_src, ip6_dst=ip6_dst, ip6_hop=ip6_hop, carried_packet=icmp6_packet_tx)
