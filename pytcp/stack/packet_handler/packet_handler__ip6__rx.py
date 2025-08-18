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
This module contains packet handler for the inbound IPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__ip6__rx.py

ver 3.0.3
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, cast

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.lib.packet_rx import PacketRx
from pytcp.protocols.enums import IpProto
from pytcp.protocols.errors import PacketValidationError
from pytcp.protocols.ip6.ip6__parser import Ip6Parser
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket


class PacketHandlerIp6Rx(ABC):
    """
    Class implements packet handler for the inbound IPv6 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Address
        from pytcp.lib.packet_stats import PacketStatsRx

        packet_stats_rx: PacketStatsRx

        # pylint: disable=unused-argument

        def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_udp(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_tcp(self, packet_rx: PacketRx, /) -> None: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip6_unicast(self) -> list[Ip6Address]: ...

        @property
        def ip6_multicast(self) -> list[Ip6Address]: ...

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv6 packets.
        """

        self.packet_stats_rx.inc("ip6__pre_parse")

        try:
            Ip6Parser(packet_rx)

        except PacketValidationError as error:
            self.packet_stats_rx.inc("ip6__failed_parse__drop")
            __debug__ and log("ip6", f"{packet_rx.tracker} - <rb>{error}</>")
            return

        __debug__ and log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6}")

        # Check if received packet has been sent to us directly or by unicast
        # or multicast.
        if packet_rx.ip6.dst not in {*self.ip6_unicast, *self.ip6_multicast}:
            self.packet_stats_rx.inc("ip6__dst_unknown__drop")
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - IP packet not destined for this stack, "
                "dropping",
            )
            return

        if packet_rx.ip6.dst in self.ip6_unicast:
            self.packet_stats_rx.inc("ip6__dst_unicast")

        if packet_rx.ip6.dst in self.ip6_multicast:
            self.packet_stats_rx.inc("ip6__dst_multicast")

        # Create RawMetadata object and try to find matching RAW socket.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=packet_rx.ip6.next,
            raw__data=bytes(
                packet_rx.ip6.payload_bytes
            ),  # memoryview: conversion for end-user interface.
            tracker=packet_rx.tracker,
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(RawSocket, stack.sockets.get(socket_id, None)):
                self.packet_stats_rx.inc("raw__socket_match")
                __debug__ and log(
                    "ip6",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening "
                    f"socket [{socket}]</>",
                )
                socket.process_raw_packet(packet_rx_md)
                return

        match packet_rx.ip6.next:
            case IpProto.IP6_FRAG:
                self._phrx_ip6_frag(packet_rx)
            case IpProto.ICMP6:
                self._phrx_icmp6(packet_rx)
            case IpProto.UDP:
                self._phrx_udp(packet_rx)
            case IpProto.TCP:
                self._phrx_tcp(packet_rx)
            case _:
                self.packet_stats_rx.inc("ip6__no_proto_support__drop")
                __debug__ and log(
                    "ip6",
                    f"{packet_rx.tracker} - Unsupported protocol "
                    f"{packet_rx.ip6.next}, dropping.",
                )
