#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# phrx_ip4.py - packet handler for inbound IPv4 packets
#


import struct
from time import time

import config
import fpp_ip4
from ip_helper import inet_cksum
from packet import PacketRx


def _defragment_ip4_packet(self, packet_rx):
    """Defragment IPv4 packet"""

    # Cleanup expired flows
    self.ip4_frag_flows = {
        _: self.ip4_frag_flows[_] for _ in self.ip4_frag_flows if self.ip4_frag_flows[_]["timestamp"] - time() < config.ip4_frag_flow_timeout
    }

    if __debug__:
        self._logger.debug(
            f"{packet_rx.tracker} - IPv4 packet fragment, offset {packet_rx.ip4.offset}, dlen {packet_rx.ip4.dlen}"
            + f"{'' if packet_rx.ip4.flag_mf else ', last'}"
        )

    flow_id = (packet_rx.ip4.src, packet_rx.ip4.dst, packet_rx.ip4.id)

    # Update flow db
    if self.ip4_frag_flows.get(flow_id, None):
        self.ip4_frag_flows[flow_id]["data"][packet_rx.ip4.offset] = packet_rx.ip4.data_copy
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
        struct.pack_into(f"{len(self.ip4_frag_flows[flow_id]['data'][offset])}s", data, offset, self.ip4_frag_flows[flow_id]["data"][offset])
    del self.ip4_frag_flows[flow_id]
    header[0] = 0x45
    struct.pack_into("!H", header, 2, fpp_ip4.IP4_HEADER_LEN + len(data))
    header[6] = header[7] = header[10] = header[11] = 0
    struct.pack_into("!H", header, 10, inet_cksum(header, 0, fpp_ip4.IP4_HEADER_LEN))
    packet_rx = PacketRx(bytes(header) + data)
    fpp_ip4.Ip4Packet(packet_rx)
    if __debug__:
        self._logger.debug(f"{packet_rx.tracker} - Reasembled fragmented IPv4 packet, dlen {len(data)} bytes")
    return packet_rx


def _phrx_ip4(self, packet_rx):
    """Handle inbound IPv4 packets"""

    fpp_ip4.Ip4Packet(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.debug(f"{packet_rx.tracker} - {packet_rx.ip4}")

    # Check if received packet has been sent to us directly or by unicast/broadcast, allow any destination if no unicast address is configured (for DHCP client)
    if self.ip4_unicast and packet_rx.ip4.dst not in {*self.ip4_unicast, *self.ip4_multicast, *self.ip4_broadcast}:
        if __debug__:
            self._logger.debug(f"{packet_rx.tracker} - IP packet not destined for this stack, dropping")
        return

    # Check if packet is a fragment and if so process it accordingly
    if packet_rx.ip4.offset != 0 or packet_rx.ip4.flag_mf:
        if not (packet_rx := _defragment_ip4_packet(self, packet_rx)):
            return

    if packet_rx.ip4.proto == fpp_ip4.IP4_PROTO_ICMP4:
        self._phrx_icmp4(packet_rx)
        return

    if packet_rx.ip4.proto == fpp_ip4.IP4_PROTO_UDP:
        self._phrx_udp(packet_rx)
        return

    if packet_rx.ip4.proto == fpp_ip4.IP4_PROTO_TCP:
        self._phrx_tcp(packet_rx)
        return
