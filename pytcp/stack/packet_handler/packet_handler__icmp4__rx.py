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
This module contains packet handler for the inbound ICMPv4 packets.

pytcp/subsystems/packet_handler/packet_handler__icmp4__rx.py

ver 3.0.4
"""


import struct
from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, IpVersion
from net_proto import (
    IP4__HEADER__LEN,
    UDP__HEADER__LEN,
    Icmp4DestinationUnreachableMessage,
    Icmp4EchoReplyMessage,
    Icmp4EchoRequestMessage,
    Icmp4Parser,
    Icmp4Type,
    IpProto,
    PacketRx,
    PacketValidationError,
)

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket


class PacketHandlerIcmp4Rx(ABC):
    """
    Class implements packet handler for the inbound ICMPv4 packets.
    """

    if TYPE_CHECKING:
        from net_proto import Icmp4Message, Tracker

        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx

        # pylint: disable=unused-argument

        def _phtx_icmp4(
            self,
            *,
            ip4__src: Ip4Address,
            ip4__dst: Ip4Address,
            icmp4__message: Icmp4Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

    def _phrx_icmp4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ICMPv4 packets.
        """

        self._packet_stats_rx.inc("icmp4__pre_parse")

        try:
            Icmp4Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self._packet_stats_rx.inc("icmp4__failed_parse__drop")
            return

        __debug__ and log("icmp4", f"{packet_rx.tracker} - {packet_rx.icmp4}")

        match packet_rx.icmp4.message.type:
            case Icmp4Type.ECHO_REPLY:
                self.__phrx_icmp4__echo_reply(packet_rx)
            case Icmp4Type.DESTINATION_UNREACHABLE:
                self.__phrx_icmp4__destination_unreachable(packet_rx)
            case Icmp4Type.ECHO_REQUEST:
                self.__phrx_icmp4__echo_request(packet_rx)
            case _:
                self.__phrx_icmp4__unknown(packet_rx)

    def __phrx_icmp4__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4EchoReplyMessage)

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Echo Reply packet "
            f"from {packet_rx.ip4.src}",
        )
        self._packet_stats_rx.inc("icmp4__echo_reply")

        # Create RawMetadata object and try to find matching RAW socket
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=IpProto.ICMP4,
            raw__data=bytes(packet_rx.icmp4.message),
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(RawSocket, stack.sockets.get(socket_id, None)):
                self._packet_stats_rx.inc("raw__socket_match")
                __debug__ and log(
                    "raw",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening "
                    f"socket [{socket}]</>",
                )
                socket.process_raw_packet(packet_rx_md)
                return

        return

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
        self._packet_stats_rx.inc("icmp4__destination_unreachable")

        # Quick and dirty way to validate received data and pull useful
        # information from it.
        frame = packet_rx.icmp4.message.data
        if (
            len(frame) >= IP4__HEADER__LEN
            and frame[0] >> 4 == 4
            and len(frame) >= ((frame[0] & 0b00001111) << 2)
            and frame[9] == IpProto.UDP
            and len(frame) >= ((frame[0] & 0b00001111) << 2) + UDP__HEADER__LEN
        ):
            # Create UdpMetadata object and try to find matching UDP socket.
            udp_offset = (frame[0] & 0b00001111) << 2
            packet = UdpMetadata(
                ip__ver=IpVersion.IP4,
                ip__local_address=Ip4Address(frame[12:16]),
                ip__remote_address=Ip4Address(frame[16:20]),
                udp__local_port=struct.unpack(
                    "!H", frame[udp_offset + 0 : udp_offset + 2]
                )[0],
                udp__remote_port=struct.unpack(
                    "!H", frame[udp_offset + 2 : udp_offset + 4]
                )[0],
            )

            for socket_id in packet.socket_ids:
                if socket := cast(
                    UdpSocket, stack.sockets.get(socket_id, None)
                ):
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
        self._packet_stats_rx.inc("icmp4__echo_request__respond_echo_reply")

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

    def __phrx_icmp4__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 packets with unknown type.
        """

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received unknown ICMPv4 packet "
            f"from {packet_rx.ip4.src}",
        )
        self._packet_stats_rx.inc("icmp4__unknown")
