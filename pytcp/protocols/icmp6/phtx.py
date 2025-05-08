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
# pylint: disable = too-many-locals
# pylint: disable = too-many-return-statements
# pylint: disable = protected-access

"""
Module contains packet handler for the outbound ICMPv6 packets.

pytcp/protocols/icmp6/phtx.py

2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.fpa import (
    Icmp6Assembler,
    Icmp6MulticastAddressRecord,
    Icmp6NdOptPI,
    Icmp6NdOptSLLA,
    Icmp6NdOptTLLA,
)
from pytcp.protocols.icmp6.ps import (
    ICMP6_ECHO_REPLY,
    ICMP6_ECHO_REQUEST,
    ICMP6_MLD2_REPORT,
    ICMP6_ND_NEIGHBOR_ADVERTISEMENT,
    ICMP6_ND_NEIGHBOR_SOLICITATION,
    ICMP6_ND_ROUTER_ADVERTISEMENT,
    ICMP6_ND_ROUTER_SOLICITATION,
    ICMP6_UNREACHABLE,
    ICMP6_UNREACHABLE__PORT,
)

if TYPE_CHECKING:
    from pytcp.lib.ip6_address import Ip6Address
    from pytcp.lib.tx_status import TxStatus
    from pytcp.subsystems.packet_handler import PacketHandler


def _phtx_icmp6(
    self: PacketHandler,
    *,
    ip6_src: Ip6Address,
    ip6_dst: Ip6Address,
    icmp6_type: int,
    icmp6_code: int = 0,
    ip6_hop: int = 64,
    icmp6_un_data: bytes | None = None,
    icmp6_ec_id: int | None = None,
    icmp6_ec_seq: int | None = None,
    icmp6_ec_data: bytes | None = None,
    icmp6_ns_target_address: Ip6Address | None = None,
    icmp6_na_flag_r: bool = False,
    icmp6_na_flag_s: bool = False,
    icmp6_na_flag_o: bool = False,
    icmp6_na_target_address: Ip6Address | None = None,
    icmp6_nd_options: (
        list[Icmp6NdOptSLLA | Icmp6NdOptTLLA | Icmp6NdOptPI] | None
    ) = None,
    icmp6_mlr2_multicast_address_record: (
        list[Icmp6MulticastAddressRecord] | None
    ) = None,
    echo_tracker: Tracker | None = None,
) -> TxStatus:
    """
    Handle outbound ICMPv6 packets.
    """

    self.packet_stats_tx.icmp6__pre_assemble += 1

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
        mlr2_multicast_address_record=(
            []
            if icmp6_mlr2_multicast_address_record is None
            else icmp6_mlr2_multicast_address_record
        ),
        echo_tracker=echo_tracker,
    )

    __debug__ and log("icmp6", f"{icmp6_packet_tx.tracker} - {icmp6_packet_tx}")

    if icmp6_type == ICMP6_ECHO_REPLY and icmp6_code == 0:
        self.packet_stats_tx.icmp6__echo_reply__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if icmp6_type == ICMP6_ECHO_REQUEST and icmp6_code == 0:
        self.packet_stats_tx.icmp6__echo_request__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if (
        icmp6_type == ICMP6_UNREACHABLE
        and icmp6_code == ICMP6_UNREACHABLE__PORT
    ):
        self.packet_stats_tx.icmp6__unreachable_port__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if icmp6_type == ICMP6_ND_ROUTER_SOLICITATION and icmp6_code == 0:
        self.packet_stats_tx.icmp6__nd_router_solicitation__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if icmp6_type == ICMP6_ND_ROUTER_ADVERTISEMENT and icmp6_code == 0:
        self.packet_stats_tx.icmp6__nd_router_advertisement__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if icmp6_type == ICMP6_ND_NEIGHBOR_SOLICITATION and icmp6_code == 0:
        self.packet_stats_tx.icmp6__nd_neighbor_solicitation__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if icmp6_type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT and icmp6_code == 0:
        self.packet_stats_tx.icmp6__nd_neighbor_advertisement__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    if icmp6_type == ICMP6_MLD2_REPORT and icmp6_code == 0:
        self.packet_stats_tx.icmp6__mld2_report__send += 1
        return self._phtx_ip6(
            ip6_src=ip6_src,
            ip6_dst=ip6_dst,
            ip6_hop=ip6_hop,
            carried_packet=icmp6_packet_tx,
        )

    # This code will never be executed in debug mode due to assertions
    # present in Packet Assembler
    self.packet_stats_tx.icmp4__unknown__drop += 1
    return TxStatus.DROPED__ICMP4__UNKNOWN
