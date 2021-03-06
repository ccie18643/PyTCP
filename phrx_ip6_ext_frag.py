#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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
# phrx_ip6_ext_frag.py - packet handler for inbound IPv6 fragment extension header
#

import struct
from time import time

import config
import fpp_ip6_ext_frag
from packet import PacketRx


def _defragment_ip6_packet(self, packet_rx):
    """ Defragment IPv6 packet """

    # Cleanup expired flows
    self.ip6_frag_flows = {
        _: self.ip6_frag_flows[_] for _ in self.ip6_frag_flows if self.ip6_frag_flows[_]["timestamp"] - time() < config.ip6_frag_flow_timeout
    }

    if __debug__:
        self._logger.debug(
            f"{packet_rx.tracker} - IPv6 packet fragment, offset {packet_rx.ip6_ext_frag.offset}, dlen {packet_rx.ip6_ext_frag.dlen}"
            + f"{'' if packet_rx.ip6_ext_frag.flag_mf else ', last'}"
        )

    flow_id = (packet_rx.ip6.src, packet_rx.ip6.dst, packet_rx.ip6_ext_frag.id)

    # Update flow db
    if self.ip6_frag_flows.get(flow_id, None):
        self.ip6_frag_flows[flow_id]["data"][packet_rx.ip6_ext_frag.offset] = packet_rx.ip6_ext_frag.data_copy
    else:
        self.ip6_frag_flows[flow_id] = {
            "header": packet_rx.ip6.header_copy,
            "timestamp": time(),
            "last": False,
            "data": {packet_rx.ip6_ext_frag.offset: packet_rx.ip6_ext_frag.data_copy},
        }
    if not packet_rx.ip6_ext_frag.flag_mf:
        self.ip6_frag_flows[flow_id]["last"] = True

    # Test if we received all fragments
    if not self.ip6_frag_flows[flow_id]["last"]:
        return None
    data_len = 0
    for offset in sorted(self.ip6_frag_flows[flow_id]["data"]):
        if offset > data_len:
            return None
        data_len = offset + len(self.ip6_frag_flows[flow_id]["data"][offset])

    # Defragment packet
    header = bytearray(self.ip6_frag_flows[flow_id]["header"])
    data = bytearray(data_len)
    for offset in sorted(self.ip6_frag_flows[flow_id]["data"]):
        struct.pack_into(f"{len(self.ip6_frag_flows[flow_id]['data'][offset])}s", data, offset, self.ip6_frag_flows[flow_id]["data"][offset])
    del self.ip6_frag_flows[flow_id]
    struct.pack_into("!H", header, 4, len(data))
    header[6] = packet_rx.ip6_ext_frag.next
    packet_rx = PacketRx(bytes(header) + data)
    if __debug__:
        self._logger.debug(f"{packet_rx.tracker} - Defragmented IPv6 packet, dlen {len(data)} bytes")
    return packet_rx


def _phrx_ip6_ext_frag(self, packet_rx):
    """ Handle inbound IPv6 fragment extension header """

    fpp_ip6_ext_frag.Ip6ExtFrag(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.debug(f"{packet_rx.tracker} - {packet_rx.ip6_ext_frag}")

    if packet_rx := _defragment_ip6_packet(self, packet_rx):
        self._phrx_ip6(packet_rx)
