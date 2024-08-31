#!/usr/bin/env python3

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


"""
Module contains packet handler for the outbound ICMPv4 packets

pytcp/protocols/icmp4/icmp4__packet_handler_tx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Message, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
)


class Icmp4PacketHandlerTx(ABC):
    """
    Class implements packet handler for the outbound ICMPv4 packets.
    """

    if TYPE_CHECKING:
        from pytcp.config import IP4__DEFAULT_TTL
        from pytcp.lib.ip4_address import Ip4Address
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.ip4.ip4__base import Ip4Payload
        from pytcp.protocols.raw.raw__assembler import RawAssembler

        packet_stats_tx: PacketStatsTx

        # pylint: disable=unused-argument

        def _phtx_ip4(
            self,
            *,
            ip4__dst: Ip4Address,
            ip4__src: Ip4Address,
            ip4__ttl: int = IP4__DEFAULT_TTL,
            ip4__payload: Ip4Payload = RawAssembler(),
        ) -> TxStatus: ...

    def _phtx_icmp4(
        self,
        *,
        ip4__src: Ip4Address,
        ip4__dst: Ip4Address,
        icmp4__message: Icmp4Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ICMPv4 packets.
        """

        self.packet_stats_tx.icmp4__pre_assemble += 1

        icmp4_packet_tx = Icmp4Assembler(
            icmp4__message=icmp4__message,
            echo_tracker=echo_tracker,
        )

        __debug__ and log(
            "icmp4", f"{icmp4_packet_tx.tracker} - {icmp4_packet_tx}"
        )

        match icmp4__message.type, icmp4__message.code:
            case Icmp4Type.ECHO_REPLY, _:
                self.packet_stats_tx.icmp4__echo_reply__send += 1
            case (
                Icmp4Type.DESTINATION_UNREACHABLE,
                Icmp4DestinationUnreachableCode.PORT,
            ):
                self.packet_stats_tx.icmp4__destination_unreachable__port__send += (
                    1
                )
            case Icmp4Type.ECHO_REQUEST, _:
                self.packet_stats_tx.icmp4__echo_request__send += 1
            case _:
                raise ValueError(
                    f"Unsupported ICMPv4 message type {icmp4__message.type}, "
                    f"code {icmp4__message.code}."
                )

        return self._phtx_ip4(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
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
        """

        return self._phtx_icmp4(
            ip4__src=ip4__local_address,
            ip4__dst=ip4__remote_address,
            icmp4__message=icmp4__message,
        )
