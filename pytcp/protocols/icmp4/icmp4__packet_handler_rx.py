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

# pylint: disable=expression-not-assigned
# pylint: disable=unused-argument


"""
Module contains packet handler for the inbound ICMPv4 packets.

pytcp/protocols/icmp4/icmp4__packet_handler_rx.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.errors import PacketValidationError
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.logger import log
from pytcp.protocols.icmp4.icmp4__parser import Icmp4Parser
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__echo_reply import (
    Icmp4EchoReplyMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    Icmp4EchoRequestMessage,
)
from pytcp.protocols.ip4.ip4__enums import Ip4Proto
from pytcp.protocols.ip4.ip4__header import IP4__HEADER__LEN
from pytcp.protocols.udp.udp__header import UDP__HEADER__LEN
from pytcp.protocols.udp.udp__metadata import UdpMetadata


class Icmp4PacketHandlerRx(ABC):
    """
    Class implements packet handler for the inbound ICMPv4 packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.packet import PacketRx
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tracker import Tracker
        from pytcp.lib.tx_status import TxStatus
        from pytcp.protocols.icmp4.icmp4__base import Icmp4Message

        packet_stats_rx: PacketStatsRx

        def _phtx_icmp4(
            self,
            *,
            ip4__src: Ip4Address,
            ip4__dst: Ip4Address,
            icmp4__message: Icmp4Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

    def _phrx_icmp4(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 packets.
        """

        self.packet_stats_rx.icmp4__pre_parse += 1

        try:
            Icmp4Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self.packet_stats_rx.icmp4__failed_parse__drop += 1
            return

        __debug__ and log("icmp4", f"{packet_rx.tracker} - {packet_rx.icmp4}")

        for message, handler in {
            Icmp4DestinationUnreachableMessage: self.__phrx_icmp4__destination_unreachable,
            Icmp4EchoRequestMessage: self.__phrx_icmp4__echo_request,
        }.items():
            if isinstance(packet_rx.icmp4.message, message):
                handler(packet_rx)
                return

    def __phrx_icmp4__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4EchoRequestMessage)

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Received ICMPv4 Echo Request "
            f"packet from {packet_rx.ip4.src}, sending reply</>",
        )
        self.packet_stats_rx.icmp4__echo_request__respond_echo_reply += 1

        self._phtx_icmp4(
            ip4__src=packet_rx.ip4.dst,
            ip4__dst=packet_rx.ip4.src,
            icmp4__message=Icmp4EchoReplyMessage(
                id=packet_rx.icmp4.message.id,
                seq=packet_rx.icmp4.message.seq,
                data=packet_rx.icmp4.message.data,
            ),
            echo_tracker=packet_rx.tracker,
        )

    def __phrx_icmp4__destination_unreachable(
        self, packet_rx: PacketRx
    ) -> None:
        """
        Handle inbound ICMPv4 Port Unreachable packets.
        """

        # TODO: The proper support for MTU Exceeded ICMPv4 message needs to be added.

        assert isinstance(
            packet_rx.icmp4.message, Icmp4DestinationUnreachableMessage
        )

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Destination Unreachable packet "
            f"from {packet_rx.ip4.src}, will try to match UDP socket",
        )
        self.packet_stats_rx.icmp4__port_unreachable += 1

        # Quick and dirty way to validate received data and pull useful
        # information from it.
        frame = packet_rx.icmp4.message.data
        if (
            len(frame) >= IP4__HEADER__LEN
            and frame[0] >> 4 == 4
            and len(frame) >= ((frame[0] & 0b00001111) << 2)
            and frame[9] == Ip4Proto.UDP
            and len(frame) >= ((frame[0] & 0b00001111) << 2) + UDP__HEADER__LEN
        ):
            # Create UdpMetadata object and try to find matching UDP socket.
            udp_offset = (frame[0] & 0b00001111) << 2
            packet = UdpMetadata(
                local_ip_address=Ip4Address(frame[12:16]),
                remote_ip_address=Ip4Address(frame[16:20]),
                local_port=struct.unpack(
                    "!H", frame[udp_offset + 0 : udp_offset + 2]
                )[0],
                remote_port=struct.unpack(
                    "!H", frame[udp_offset + 2 : udp_offset + 4]
                )[0],
            )

            for socket_pattern in packet.socket_patterns:
                socket = stack.sockets.get(socket_pattern, None)
                if socket:
                    __debug__ and log(
                        "icmp4",
                        f"{packet_rx.tracker} - <INFO>Found matching "
                        f"listening socket {socket}, for Unreachable "
                        f"packet from {packet_rx.ip4.src}</>",
                    )
                    socket.notify_unreachable()
                    return

            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - Unreachable data doesn't match "
                "any UDP socket",
            )
            return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Unreachable data doesn't pass basic "
            "IPv4/UDP integrity check",
        )
