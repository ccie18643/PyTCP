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
Module contains packet handler for the inbound IPv4 packets.

pytcp/protocols/ip4/phrx.py

ver 2.7
"""


from __future__ import annotations

import struct
from time import time
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.fpp import Ip4Parser
from pytcp.protocols.ip4.ps import (
    IP4_HEADER_LEN,
    IP4_PROTO_ICMP4,
    IP4_PROTO_TCP,
    IP4_PROTO_UDP,
)

if TYPE_CHECKING:
    from pytcp.subsystems.packet_handler import PacketHandler


def _defragment_ip4_packet(
    self: PacketHandler, packet_rx: PacketRx
) -> PacketRx | None:
    """
    Defragment IPv4 packet.
    """

    # Cleanup expired flows
    self.ip4_frag_flows = {
        _: self.ip4_frag_flows[_]
        for _ in self.ip4_frag_flows
        if self.ip4_frag_flows[_]["timestamp"] - time()
        < config.IP4_FRAG_FLOW_TIMEOUT
    }

    __debug__ and log(
        "ip4",
        f"{packet_rx.tracker} - IPv4 packet fragment, offset "
        f"{packet_rx.ip4.offset}, dlen {packet_rx.ip4.dlen}"
        f"{'' if packet_rx.ip4.flag_mf else ', last'}",
    )

    flow_id = (packet_rx.ip4.src, packet_rx.ip4.dst, packet_rx.ip4.id)

    # Update flow db
    if flow_id in self.ip4_frag_flows:
        self.ip4_frag_flows[flow_id]["data"][
            packet_rx.ip4.offset
        ] = packet_rx.ip4.data_copy
    else:
        self.ip4_frag_flows[flow_id] = {
            "header": packet_rx.ip4.header_copy,
            "timestamp": time(),
            "last": False,
            "data": {packet_rx.ip4.offset: packet_rx.ip4.data_copy},
        }
    if not packet_rx.ip4.flag_mf:
        self.ip4_frag_flows[flow_id]["last"] = True

    # Test if we received all fragments
    if not self.ip4_frag_flows[flow_id]["last"]:
        return None
    data_len = 0
    for offset in sorted(self.ip4_frag_flows[flow_id]["data"]):
        if offset > data_len:
            return None
        data_len = offset + len(self.ip4_frag_flows[flow_id]["data"][offset])

    # Defragment packet
    header = bytearray(self.ip4_frag_flows[flow_id]["header"])
    data = bytearray(data_len)
    for offset in sorted(self.ip4_frag_flows[flow_id]["data"]):
        struct.pack_into(
            f"{len(self.ip4_frag_flows[flow_id]['data'][offset])}s",
            data,
            offset,
            self.ip4_frag_flows[flow_id]["data"][offset],
        )
    del self.ip4_frag_flows[flow_id]
    header[0] = 0x45
    struct.pack_into("!H", header, 2, IP4_HEADER_LEN + len(data))
    header[6] = header[7] = header[10] = header[11] = 0
    struct.pack_into("!H", header, 10, inet_cksum(memoryview(header)))
    packet_rx = PacketRx(bytes(header) + data)
    Ip4Parser(packet_rx)
    __debug__ and log(
        "ip4",
        f"{packet_rx.tracker} - Reassembled fragmented IPv4 packet, "
        f"dlen {len(data)} bytes",
    )
    return packet_rx


def _phrx_ip4(self: PacketHandler, packet_rx: PacketRx) -> None:
    """Handle inbound IPv4 packets"""

    self.packet_stats_rx.ip4__pre_parse += 1

    Ip4Parser(packet_rx)

    if packet_rx.parse_failed:
        self.packet_stats_rx.ip4__failed_parse__drop += 1
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
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
            defragmented_packet_rx := self._defragment_ip4_packet(packet_rx)
        ):
            return
        packet_rx = defragmented_packet_rx
        self.packet_stats_rx.ip4__defrag += 1

    if packet_rx.ip4.proto == IP4_PROTO_ICMP4:
        self._phrx_icmp4(packet_rx)
        return

    if packet_rx.ip4.proto == IP4_PROTO_UDP:
        self._phrx_udp(packet_rx)
        return

    if packet_rx.ip4.proto == IP4_PROTO_TCP:
        self._phrx_tcp(packet_rx)
        return
