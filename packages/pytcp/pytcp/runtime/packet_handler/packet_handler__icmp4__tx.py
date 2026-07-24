################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains packet handler for the outbound ICMPv4 packets

pytcp/runtime/packet_handler/packet_handler__icmp4__tx.py

ver 3.0.9
"""

from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4Message,
    Icmp4Type,
    Ip4Options,
    Tracker,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class Icmp4TxHandler:
    """
    The outbound ICMPv4 packet handler for one interface.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phtx_icmp4(
        self,
        *,
        ip4__src: Ip4Address,
        ip4__dst: Ip4Address,
        ip4__options: Ip4Options = Ip4Options(),
        icmp4__message: Icmp4Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ICMPv4 packets.
        """

        self._if._packet_stats_tx.icmp4__pre_assemble += 1

        icmp4_packet_tx = Icmp4Assembler(
            icmp4__message=icmp4__message,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("icmp4", f"{icmp4_packet_tx.tracker} - {icmp4_packet_tx}")

        match icmp4__message.type, icmp4__message.code:
            case Icmp4Type.ECHO_REPLY, _:
                self._if._packet_stats_tx.icmp4__echo_reply__send += 1
            case (
                Icmp4Type.DESTINATION_UNREACHABLE,
                Icmp4DestinationUnreachableCode.PORT,
            ):
                self._if._packet_stats_tx.icmp4__destination_unreachable__port__send += 1
            case (
                Icmp4Type.DESTINATION_UNREACHABLE,
                Icmp4DestinationUnreachableCode.PROTOCOL,
            ):
                self._if._packet_stats_tx.icmp4__destination_unreachable__protocol__send += 1
            case Icmp4Type.PARAMETER_PROBLEM, _:
                self._if._packet_stats_tx.icmp4__parameter_problem__send += 1
            case Icmp4Type.ECHO_REQUEST, _:
                self._if._packet_stats_tx.icmp4__echo_request__send += 1
            case _:
                # Defensive drop: unsupported ICMPv4 type/code shouldn't
                # reach the TX path (the call sites enumerate their
                # message types), but if one does, count + drop is
                # robust where 'raise' would crash the calling thread.
                self._if._packet_stats_tx.icmp4__unknown__drop += 1
                __debug__ and log(
                    "icmp4",
                    f"{icmp4_packet_tx.tracker} - <CRIT>Dropping unsupported ICMPv4 "
                    f"type {icmp4__message.type}, code {icmp4__message.code}</>",
                )
                return TxStatus.DROPPED__ICMP4__UNKNOWN

        return self._if._phtx_ip4(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__options=ip4__options,
            ip4__payload=icmp4_packet_tx,
        )

    def send_icmp4_packet(
        self,
        *,
        ip4__local_address: Ip4Address,
        ip4__remote_address: Ip4Address,
        icmp4__message: Icmp4Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv4 Socket -> FPA communication.
        Marshaled onto the interface's TX worker via '_marshal_tx'.
        """

        return self._if._marshal_tx(
            lambda: self._phtx_icmp4(
                ip4__src=ip4__local_address,
                ip4__dst=ip4__remote_address,
                icmp4__message=icmp4__message,
            )
        )
