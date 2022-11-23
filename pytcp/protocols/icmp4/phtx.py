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
Module contains packet handler for the outbound ICMPv4 packets

pytcp/protocols/icmp4/phtx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp4.fpa import Icmp4Assembler
from pytcp.protocols.icmp4.ps import (
    ICMP4_ECHO_REPLY,
    ICMP4_ECHO_REQUEST,
    ICMP4_UNREACHABLE,
    ICMP4_UNREACHABLE__PORT,
)

if TYPE_CHECKING:
    from pytcp.lib.ip4_address import Ip4Address
    from pytcp.subsystems.packet_handler import PacketHandler


def _phtx_icmp4(
    self: PacketHandler,
    *,
    ip4_src: Ip4Address,
    ip4_dst: Ip4Address,
    icmp4_type: int,
    icmp4_code: int = 0,
    icmp4_ec_id: int | None = None,
    icmp4_ec_seq: int | None = None,
    icmp4_ec_data: bytes | None = None,
    icmp4_un_data: bytes | None = None,
    echo_tracker: Tracker | None = None,
) -> TxStatus:
    """
    Handle outbound ICMPv4 packets.
    """

    self.packet_stats_tx.icmp4__pre_assemble += 1

    icmp4_packet_tx = Icmp4Assembler(
        type=icmp4_type,
        code=icmp4_code,
        ec_id=icmp4_ec_id,
        ec_seq=icmp4_ec_seq,
        ec_data=icmp4_ec_data,
        un_data=icmp4_un_data,
        echo_tracker=echo_tracker,
    )

    __debug__ and log("icmp4", f"{icmp4_packet_tx.tracker} - {icmp4_packet_tx}")

    if icmp4_type == ICMP4_ECHO_REPLY and icmp4_code == 0:
        self.packet_stats_tx.icmp4__echo_reply__send += 1
        return self._phtx_ip4(
            ip4_src=ip4_src, ip4_dst=ip4_dst, carried_packet=icmp4_packet_tx
        )

    if icmp4_type == ICMP4_ECHO_REQUEST and icmp4_code == 0:
        self.packet_stats_tx.icmp4__echo_request__send += 1
        return self._phtx_ip4(
            ip4_src=ip4_src, ip4_dst=ip4_dst, carried_packet=icmp4_packet_tx
        )

    if (
        icmp4_type == ICMP4_UNREACHABLE
        and icmp4_code == ICMP4_UNREACHABLE__PORT
    ):
        self.packet_stats_tx.icmp4__unreachable_port__send += 1
        return self._phtx_ip4(
            ip4_src=ip4_src, ip4_dst=ip4_dst, carried_packet=icmp4_packet_tx
        )

    # This code will never be executed in debug mode due to assertions present
    # in Packet Assembler
    self.packet_stats_tx.icmp4__unknown__drop += 1
    return TxStatus.DROPED__ICMP4__UNKNOWN
