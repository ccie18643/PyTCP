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
# phrx_ipv4.py - packet handler for inbound IPv4 packets
#


import inet_cksum
import ps_icmpv4
import ps_ipv4
import ps_tcp
import ps_udp

ipv4_fragments = {}


def handle_ipv4_fragmentation(ipv4_packet_rx):
    """ Check if packet is fragmented """

    # Check if IP packet is a first fragment
    if ipv4_packet_rx.ipv4_frag_offset == 0 and ipv4_packet_rx.ipv4_frag_mf:
        ipv4_fragments[ipv4_packet_rx.ipv4_packet_id] = {}
        ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][ipv4_packet_rx.ipv4_frag_offset] = ipv4_packet_rx.raw_data
        return None

    # Check if IP packet is one of middle fragments
    if ipv4_packet_rx.ipv4_frag_offset != 0 and ipv4_packet_rx.ipv4_frag_mf:
        # Check if packet is part of existing fagment flow
        if ipv4_fragments.get(ipv4_packet_rx.ipv4_packet_id, None):
            ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][ipv4_packet_rx.ipv4_frag_offset] = ipv4_packet_rx.raw_data
        return None

    # Check if IP packet is last fragment
    if ipv4_packet_rx.ipv4_frag_offset != 0 and not ipv4_packet_rx.ipv4_frag_mf:

        # Check if packet is part of existing fagment flow
        if ipv4_fragments.get(ipv4_packet_rx.ipv4_packet_id, None):
            ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][ipv4_packet_rx.ipv4_frag_offset] = ipv4_packet_rx.raw_data

            raw_data = b""
            for offset in sorted(ipv4_fragments[ipv4_packet_rx.ipv4_packet_id]):
                raw_data += ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][offset]

            # Craft complete IP packet based on last fragment for further processing
            ipv4_packet_rx.ipv4_frag_mf = False
            ipv4_packet_rx.ipv4_frag_offset = 0
            ipv4_packet_rx.ipv4_plen = ipv4_packet_rx.ipv4_hlen + len(raw_data)
            ipv4_packet_rx.ipv4_cksum = 0
            ipv4_packet_rx.ipv4_cksum = inet_cksum.compute_cksum(ipv4_packet_rx.raw_header)
            ipv4_packet_rx.raw_data = raw_data

    return ipv4_packet_rx


def phrx_ipv4(self, ipv4_packet_rx):
    """ Handle inbound IP packets """

    self.logger.debug(f"{ipv4_packet_rx.tracker} - {ipv4_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast/broadcast
    if ipv4_packet_rx.ipv4_dst not in {*self.stack_ipv4_unicast, *self.stack_ipv4_multicast, *self.stack_ipv4_broadcast}:
        self.logger.debug(f"{ipv4_packet_rx.tracker} - IP packet not destined for this stack, droping")
        return

    # Validate IP header checksum
    if not ipv4_packet_rx.validate_cksum():
        self.logger.debug(f"{ipv4_packet_rx.tracker} - IP packet has invalid checksum, droping")
        return

    # Check if packet is a fragment, and if so process it accrdingly
    ipv4_packet_rx = handle_ipv4_fragmentation(ipv4_packet_rx)
    if not ipv4_packet_rx:
        return

    if ipv4_packet_rx.ipv4_proto == ps_ipv4.IP4_PROTO_ICMP4:
        self.phrx_icmpv4(ipv4_packet_rx, ps_icmpv4.Icmp4Packet(ipv4_packet_rx))
        return

    if ipv4_packet_rx.ipv4_proto == ps_ipv4.IP4_PROTO_UDP:
        self.phrx_udp(ipv4_packet_rx, ps_udp.UdpPacket(ipv4_packet_rx))
        return

    if ipv4_packet_rx.ipv4_proto == ps_ipv4.IP4_PROTO_TCP:
        self.phrx_tcp(ipv4_packet_rx, ps_tcp.TcpPacket(ipv4_packet_rx))
        return
