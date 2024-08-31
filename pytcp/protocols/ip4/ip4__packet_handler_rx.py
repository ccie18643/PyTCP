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
Module contains packet handler for the inbound IPv4 packets.

pytcp/protocols/ip4/ip4__packet_handler_rx.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from time import time
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.errors import PacketValidationError
from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__enums import Ip4Proto
from pytcp.protocols.ip4.ip4__header import IP4__HEADER__LEN
from pytcp.protocols.ip4.ip4__parser import Ip4Parser


class Ip4PacketHandlerRx(ABC):
    """
    Class implements packet handler for the inbound IPv4 packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.ip4_address import Ip4Address
        from pytcp.lib.packet_stats import PacketStatsRx

        packet_stats_rx: PacketStatsRx
        ip4_multicast: list[Ip4Address]
        ip4_frag_flows: dict[tuple[Ip4Address, Ip4Address, int], dict]

        # pylint: disable=unused-argument

        def _phrx_icmp4(self, packet_rx: PacketRx) -> None: ...
        def _phrx_udp(self, packet_rx: PacketRx) -> None: ...
        def _phrx_tcp(self, packet_rx: PacketRx) -> None: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip4_unicast(self) -> list[Ip4Address]: ...

        @property
        def ip4_broadcast(self) -> list[Ip4Address]: ...

    def _phrx_ip4(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound IPv4 packets.
        """

        self.packet_stats_rx.ip4__pre_parse += 1

        try:
            Ip4Parser(packet_rx)

        except PacketValidationError as error:
            self.packet_stats_rx.ip4__failed_parse__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ip4", f"{packet_rx.tracker} - {packet_rx.ip4}")

        # Check if received packet has been sent to us directly or by
        # unicast/broadcast, allow any destination if no unicast address
        # is configured (for DHCP client).
        if self.ip4_unicast and packet_rx.ip4.dst not in {
            *self.ip4_unicast,
            *self.ip4_multicast,
            *self.ip4_broadcast,
        }:
            self.packet_stats_rx.ip4__dst_unknown__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - IP packet not destined for this stack, "
                "dropping",
            )
            return

        if packet_rx.ip4.dst in self.ip4_unicast:
            self.packet_stats_rx.ip4__dst_unicast += 1

        if packet_rx.ip4.dst in self.ip4_multicast:
            self.packet_stats_rx.ip4__dst_multicast += 1

        if packet_rx.ip4.dst in self.ip4_broadcast:
            self.packet_stats_rx.ip4__dst_broadcast += 1

        # Check if packet is a fragment and if so process it accordingly
        if packet_rx.ip4.offset != 0 or packet_rx.ip4.flag_mf:
            self.packet_stats_rx.ip4__frag += 1
            if not (
                defragmented_packet_rx := self.__defragment_ip4_packet(
                    packet_rx
                )
            ):
                return
            packet_rx = defragmented_packet_rx
            self.packet_stats_rx.ip4__defrag += 1

        match packet_rx.ip4.proto:
            case Ip4Proto.ICMP4:
                self._phrx_icmp4(packet_rx)
            case Ip4Proto.UDP:
                self._phrx_udp(packet_rx)
            case Ip4Proto.TCP:
                self._phrx_tcp(packet_rx)
            case _:
                self.packet_stats_rx.ip4__no_proto_support__drop += 1
                __debug__ and log(
                    "ip4",
                    f"{packet_rx.tracker} - Unsupported protocol "
                    f"{packet_rx.ip4.proto}, dropping.",
                )

    def __defragment_ip4_packet(self, packet_rx: PacketRx) -> PacketRx | None:
        """
        Defragment IPv4 packet.
        """

        # Cleanup expired flows
        self.ip4_frag_flows = {
            flow: self.ip4_frag_flows[flow]
            for flow in self.ip4_frag_flows
            if self.ip4_frag_flows[flow]["timestamp"] - time()
            < config.IP4__FRAG_FLOW_TIMEOUT
        }

        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - IPv4 packet fragment, offset "
            f"{packet_rx.ip4.offset}, dlen {packet_rx.ip4.payload_len}"
            f"{'' if packet_rx.ip4.flag_mf else ', last'}",
        )

        flow_id = (packet_rx.ip4.src, packet_rx.ip4.dst, packet_rx.ip4.id)

        # Update flow db
        if flow_id in self.ip4_frag_flows:
            self.ip4_frag_flows[flow_id]["payload"][
                packet_rx.ip4.offset
            ] = packet_rx.ip4.payload_bytes
        else:
            self.ip4_frag_flows[flow_id] = {
                "header": packet_rx.ip4.header_bytes,
                "timestamp": time(),
                "last": False,
                "payload": {packet_rx.ip4.offset: packet_rx.ip4.payload_bytes},
            }
        if not packet_rx.ip4.flag_mf:
            self.ip4_frag_flows[flow_id]["last"] = True

        # Test if we received all fragments
        if not self.ip4_frag_flows[flow_id]["last"]:
            return None
        payload_len = 0
        for offset in sorted(self.ip4_frag_flows[flow_id]["payload"]):
            if offset > payload_len:
                return None
            payload_len = offset + len(
                self.ip4_frag_flows[flow_id]["payload"][offset]
            )

        # Defragment packet
        header = bytearray(self.ip4_frag_flows[flow_id]["header"])
        payload = bytearray(payload_len)
        for offset in sorted(self.ip4_frag_flows[flow_id]["payload"]):
            struct.pack_into(
                f"{len(self.ip4_frag_flows[flow_id]['payload'][offset])}s",
                payload,
                offset,
                bytes(self.ip4_frag_flows[flow_id]["payload"][offset]),
            )
        del self.ip4_frag_flows[flow_id]
        header[0] = 0x45
        struct.pack_into("!H", header, 2, IP4__HEADER__LEN + len(payload))
        header[6] = header[7] = header[10] = header[11] = 0
        struct.pack_into("!H", header, 10, inet_cksum(memoryview(header)))
        packet_rx = PacketRx(bytes(header) + payload)
        Ip4Parser(packet_rx)
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - Reasembled fragmented IPv4 packet, "
            f"dlen {len(payload)} bytes",
        )
        return packet_rx
