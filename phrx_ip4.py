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


import ps_icmp4
import ps_ip4
import ps_tcp
import ps_udp
from ip_helper import inet_cksum

ip4_fragments = {}


def handle_ip4_fragmentation(ip4_packet_rx):
    """Check if packet is fragmented"""

    # Check if IP packet is a first fragment
    if ip4_packet_rx.ip4_frag_offset == 0 and ip4_packet_rx.ip4_flag_mf:
        ip4_fragments[ip4_packet_rx.ip4_packet_id] = {}
        ip4_fragments[ip4_packet_rx.ip4_packet_id][ip4_packet_rx.ip4_frag_offset] = ip4_packet_rx.raw_data
        return None

    # Check if IP packet is one of middle fragments
    if ip4_packet_rx.ip4_frag_offset != 0 and ip4_packet_rx.ip4_flag_mf:
        # Check if packet is part of existing fagment flow
        if ip4_fragments.get(ip4_packet_rx.ip4_packet_id, None):
            ip4_fragments[ip4_packet_rx.ip4_packet_id][ip4_packet_rx.ip4_frag_offset] = ip4_packet_rx.raw_data
        return None

    # Check if IP packet is last fragment
    if ip4_packet_rx.ip4_frag_offset != 0 and not ip4_packet_rx.ip4_flag_mf:

        # Check if packet is part of existing fagment flow
        if ip4_fragments.get(ip4_packet_rx.ip4_packet_id, None):
            ip4_fragments[ip4_packet_rx.ip4_packet_id][ip4_packet_rx.ip4_frag_offset] = ip4_packet_rx.raw_data

            raw_data = b""
            for offset in sorted(ip4_fragments[ip4_packet_rx.ip4_packet_id]):
                raw_data += ip4_fragments[ip4_packet_rx.ip4_packet_id][offset]

            # Craft complete IP packet based on last fragment for further processing
            ip4_packet_rx.ip4_flag_mf = False
            ip4_packet_rx.ip4_frag_offset = 0
            ip4_packet_rx.ip4_plen = ip4_packet_rx.ip4_hlen + len(raw_data)
            ip4_packet_rx.ip4_cksum = 0
            ip4_packet_rx.ip4_cksum = inet_cksum(ip4_packet_rx.raw_header)
            ip4_packet_rx.raw_data = raw_data

    return ip4_packet_rx


def phrx_ip4(self, ip4_packet_rx):
    """Handle inbound IP packets"""

    # Validate IPv4 packet sanity
    if ip4_packet_rx.sanity_check_failed:
        return

    if __debug__:
        self._logger.debug(f"{ip4_packet_rx.tracker} - {ip4_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast/broadcast, allow any destination if no unicast address is configured (for DHCP client)
    if self.ip4_unicast and ip4_packet_rx.ip4_dst not in {*self.ip4_unicast, *self.ip4_multicast, *self.ip4_broadcast}:
        if __debug__:
            self._logger.debug(f"{ip4_packet_rx.tracker} - IP packet not destined for this stack, dropping")
        return

    # Check if packet is a fragment, and if so process it accordingly
    ip4_packet_rx = handle_ip4_fragmentation(ip4_packet_rx)
    if not ip4_packet_rx:
        return

    if ip4_packet_rx.ip4_proto == ps_ip4.IP4_PROTO_ICMP4:
        self.phrx_icmp4(ip4_packet_rx, ps_icmp4.Icmp4Packet(ip4_packet_rx))
        return

    if ip4_packet_rx.ip4_proto == ps_ip4.IP4_PROTO_UDP:
        self.phrx_udp(ip4_packet_rx, ps_udp.UdpPacket(ip4_packet_rx))
        return

    if ip4_packet_rx.ip4_proto == ps_ip4.IP4_PROTO_TCP:
        self.phrx_tcp(ip4_packet_rx, ps_tcp.TcpPacket(ip4_packet_rx))
        return
