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
Module contains packet handler for the inbound UDP packets.

pytcp/protocols/udp/udp__packet_handler_rx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address
from pytcp import config
from pytcp.lib import stack
from pytcp.lib.errors import PacketValidationError
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp4.icmp4__base import Icmp4Message
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
    Icmp4DestinationUnreachableMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6DestinationUnreachableMessage,
)
from pytcp.protocols.udp.udp__parser import UdpParser
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket


class PacketHandlerUdpRx(ABC):
    """
    Class implements packet handler for the inbound UDP packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Address, IpAddress
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tracker import Tracker
        from pytcp.lib.tx_status import TxStatus
        from pytcp.protocols.icmp6.icmp6__base import Icmp6Message

        packet_stats_rx: PacketStatsRx

        # pylint: disable=unused-argument

        def _phtx_udp(
            self,
            *,
            ip__src: IpAddress,
            ip__dst: IpAddress,
            udp__sport: int,
            udp__dport: int,
            udp__payload: bytes = bytes(),
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        def _phtx_icmp4(
            self,
            *,
            ip4__src: Ip4Address,
            ip4__dst: Ip4Address,
            icmp4__message: Icmp4Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        def _phtx_icmp6(
            self,
            *,
            ip6__src: Ip6Address,
            ip6__dst: Ip6Address,
            ip6__hop: int = 64,
            icmp6__message: Icmp6Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound UDP packets.
        """

        self.packet_stats_rx.udp__pre_parse += 1

        try:
            UdpParser(packet_rx)

        except PacketValidationError as error:
            self.packet_stats_rx.udp__failed_parse__drop += 1
            __debug__ and log(
                "udp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("udp", f"{packet_rx.tracker} - {packet_rx.udp}")

        assert isinstance(
            packet_rx.udp.payload, memoryview
        )  # memoryview: data type check point

        # Create UdpMetadata object and try to find matching UDP socket
        packet_rx_md = UdpMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            udp__local_port=packet_rx.udp.dport,
            ip__remote_address=packet_rx.ip.src,
            udp__remote_port=packet_rx.udp.sport,
            udp__data=bytes(
                packet_rx.udp.payload
            ),  # memoryview: conversion for end-user interface
            tracker=packet_rx.tracker,
        )

        for socket_pattern in packet_rx_md.socket_patterns:
            if socket := cast(
                UdpSocket, stack.sockets.get(socket_pattern, None)
            ):
                self.packet_stats_rx.udp__socket_match += 1
                __debug__ and log(
                    "udp",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening "
                    f"socket [{socket}]</>",
                )
                socket.process_udp_packet(packet_rx_md)
                return

        # Silently drop packet if it's source address is unspecified.
        if packet_rx.ip.src.is_unspecified:
            self.packet_stats_rx.udp__ip_source_unspecified += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - Received UDP packet from "
                f"{packet_rx.ip.src}, port {packet_rx.udp.sport} to "
                f"{packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping",
            )
            return

        # Handle the UDP Echo operation in case its enabled
        # (used for packet flow unit testing only).
        if (
            config.UDP__ECHO_NATIVE__DISABLED is False
            and packet_rx.udp.dport == 7
        ):
            self.packet_stats_rx.udp__echo_native__respond_udp += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <INFO>Performing native "
                "UDP Echo operation</>",
            )

            self._phtx_udp(
                ip__src=packet_rx.ip.dst,
                ip__dst=packet_rx.ip.src,
                udp__sport=packet_rx.udp.sport,
                udp__dport=packet_rx.udp.dport,
                udp__payload=packet_rx.udp.payload,
            )
            return

        # Respond with ICMPv4 Port Unreachable message if no matching
        # socket has been found.
        __debug__ and log(
            "udp",
            f"{packet_rx_md.tracker} - Received UDP packet from "
            f"{packet_rx.ip.src} to closed port "
            f"{packet_rx.udp.dport}, sending ICMPv4 Port Unreachable",
        )

        match packet_rx.ip.ver:
            case 6:
                self.packet_stats_rx.udp__no_socket_match__respond_icmp6_unreachable += (
                    1
                )
                self._phtx_icmp6(
                    ip6__src=packet_rx.ip6.dst,
                    ip6__dst=packet_rx.ip6.src,
                    icmp6__message=Icmp6DestinationUnreachableMessage(
                        code=Icmp6DestinationUnreachableCode.PORT,
                        data=packet_rx.ip.packet_bytes,
                    ),
                    echo_tracker=packet_rx.tracker,
                )
            case 4:
                self.packet_stats_rx.udp__no_socket_match__respond_icmp4_unreachable += (
                    1
                )
                self._phtx_icmp4(
                    ip4__src=packet_rx.ip4.dst,
                    ip4__dst=packet_rx.ip4.src,
                    icmp4__message=Icmp4DestinationUnreachableMessage(
                        code=Icmp4DestinationUnreachableCode.PORT,
                        data=packet_rx.ip.packet_bytes,
                    ),
                    echo_tracker=packet_rx.tracker,
                )
