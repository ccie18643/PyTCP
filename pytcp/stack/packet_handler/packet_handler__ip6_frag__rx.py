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
Module contains packet handler for inbound the IPv6 fragment extension header.

pytcp/subsystems/packet_handler/packet_handler__ip6_frag__rx.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from time import time
from typing import TYPE_CHECKING

from pytcp import stack
from pytcp.lib.ip_frag import IpFragData, IpFragFlowId
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6_frag.ip6_frag__parser import Ip6FragParser


class PacketHandlerIp6FragRx(ABC):
    """
    Class implements packet handler for inbound the IPv6 fragment extension.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Address
        from pytcp.lib.packet_stats import PacketStatsRx

        packet_stats_rx: PacketStatsRx
        ip6_frag_flows: dict[IpFragFlowId, IpFragData]

        # pylint: disable=unused-argument

        def _phrx_ip6(self, packet_rx: PacketRx) -> None: ...

    def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv6 fragment extension header.
        """

        self.packet_stats_rx.ip6_frag__pre_parse += 1

        Ip6FragParser(packet_rx)

        if packet_rx.parse_failed:
            self.packet_stats_rx.ip6_frag__failed_parse += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
            )
            return

        __debug__ and log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6_frag}")

        if defragmented_packet_rx := self.__defragment_ip6_packet(packet_rx):
            self.packet_stats_rx.ip6_frag__defrag += 1
            self._phrx_ip6(
                defragmented_packet_rx,
            )

    def __defragment_ip6_packet(self, packet_rx: PacketRx) -> PacketRx | None:
        """
        Defragment IPv6 packet.
        """

        # Cleanup expired flows.
        self.ip6_frag_flows = {
            flow: self.ip6_frag_flows[flow]
            for flow in self.ip6_frag_flows
            if self.ip6_frag_flows[flow].timestamp - time()
            < stack.IP6__FRAG_FLOW_TIMEOUT
        }

        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - IPv6 packet fragment, "
            f"offset {packet_rx.ip6_frag.offset}, "
            f"len {len(packet_rx.ip6_frag.payload)}"
            f"{'' if packet_rx.ip6_frag.flag_mf else ', last'}",
        )

        flow_id = IpFragFlowId(
            src=packet_rx.ip6.src,
            dst=packet_rx.ip6.dst,
            id=packet_rx.ip6_frag.id,
        )

        # Update flow db
        if flow_id in self.ip6_frag_flows:
            self.ip6_frag_flows[flow_id].payload[
                packet_rx.ip6_frag.offset
            ] = packet_rx.ip6_frag.payload_bytes
        else:
            self.ip6_frag_flows[flow_id] = IpFragData(
                header=packet_rx.ip6.header_bytes,
                payload={
                    packet_rx.ip6_frag.offset: packet_rx.ip6_frag.payload_bytes
                },
            )
        if not packet_rx.ip6_frag.flag_mf:
            self.ip6_frag_flows[flow_id].last = True

        # Test if we received all fragments
        if not self.ip6_frag_flows[flow_id].last:
            return None
        payload_len = 0
        for offset in sorted(self.ip6_frag_flows[flow_id].payload):
            if offset > payload_len:
                return None
            payload_len = offset + len(
                self.ip6_frag_flows[flow_id].payload[offset]
            )

        # Defragment packet
        header = bytearray(self.ip6_frag_flows[flow_id].header)
        payload = bytearray(payload_len)
        for offset in sorted(self.ip6_frag_flows[flow_id].payload):
            struct.pack_into(
                f"{len(self.ip6_frag_flows[flow_id].payload[offset])}s",
                payload,
                offset,
                self.ip6_frag_flows[flow_id].payload[offset],
            )
        del self.ip6_frag_flows[flow_id]
        struct.pack_into("!H", header, 4, len(payload))
        header[6] = int(packet_rx.ip6_frag.next)
        packet_rx = PacketRx(bytes(header) + payload)
        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - Defragmented IPv6 packet, "
            f"payload len {len(payload)} bytes",
        )
        return packet_rx
