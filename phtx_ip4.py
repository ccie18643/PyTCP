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
# phtx_ip4.py - packet handler for outbound IPv4 packets
#


import socket
import struct
from ipaddress import IPv4Address

import ps_ether
import ps_ip4
import stack


def validate_src_ip4_address(self, ip4_src, ip4_dst):
    """ Make sure source ip address is valid, supplemt with valid one as appropriate """

    # Check if the the source IP address belongs to this stack or its set to all zeros (for DHCP client comunication)
    if ip4_src not in {*self.stack_ip4_unicast, *self.stack_ip4_multicast, *self.stack_ip4_broadcast, IPv4Address("0.0.0.0")}:
        self.logger.warning(f"Unable to sent out IPv4 packet, stack doesn't own IPv4 address {ip4_src}")
        return None

    # If packet is a response to multicast then replace source address with primary address of the stack
    if ip4_src in self.stack_ip4_multicast:
        if self.stack_ip4_unicast:
            ip4_src = self.stack_ip4_unicast[0]
            self.logger.debug(f"Packet is response to multicast, replaced source with stack primary IPv4 address {ip4_src}")
        else:
            self.logger.warning("Unable to sent out IPv4 packet, no stack primary unicast IPv4 address available")
            return None

    # If packet is a response to limited broadcast then replace source address with primary address of the stack
    if ip4_src == IPv4Address("255.255.255.255"):
        if self.stack_ip4_unicast:
            ip4_src = self.stack_ip4_unicast[0]
            self.logger.debug(f"Packet is response to limited broadcast, replaced source with stack primary IPv4 address {ip4_src}")
        else:
            self.logger.warning("Unable to sent out IPv4 packet, no stack primary unicast IPv4 address available")
            return None

    # If packet is a response to directed braodcast then replace source address with first stack address that belongs to appropriate subnet
    if ip4_src in self.stack_ip4_broadcast:
        ip4_src = [_.ip for _ in self.stack_ip4_address if _.network.broadcast_address == ip4_src]
        if ip4_src:
            ip4_src = ip4_src[0]
            self.logger.debug(f"Packet is response to directed broadcast, replaced source with apropriate IPv4 address {ip4_src}")
        else:
            self.logger.warning("Unable to sent out IPv4 packet, no appropriate stack unicast IPv4 address available")
            return None

    # If source is unspecified check if destination belongs to any of local networks, if so pick source address from that network
    if ip4_src.is_unspecified:
        for stack_ip4_address in self.stack_ip4_address:
            if ip4_dst in stack_ip4_address.network:
                return stack_ip4_address.ip

    # If source unspcified and destination is external pick source from first network that has default gateway set
    if ip4_src.is_unspecified:
        for stack_ip4_address in self.stack_ip4_address:
            if stack_ip4_address.gateway:
                return stack_ip4_address.ip

    return ip4_src


def validate_dst_ip4_address(self, ip4_dst):
    """ Make sure destination ip address is valid """

    # Drop packet if the destination address is unspecified
    if ip4_dst.is_unspecified:
        self.logger.warning("Destination address is unspecified, dropping...")
        return None

    return ip4_dst


def phtx_ip4(self, child_packet, ip4_dst, ip4_src):
    """ Handle outbound IP packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not stack.ip4_support:
        return

    # Make sure source and destination addresses are the right object type
    ip4_src = IPv4Address(ip4_src)
    ip4_dst = IPv4Address(ip4_dst)

    # Validate source address
    ip4_src = validate_src_ip4_address(self, ip4_src, ip4_dst)
    if not ip4_src:
        return

    # Validate destination address
    ip4_dst = validate_dst_ip4_address(self, ip4_dst)
    if not ip4_dst:
        return

    # Generate new IPv4 ID
    self.ip4_packet_id += 1
    if self.ip4_packet_id > 65535:
        self.ip4_packet_id = 1

    # Check if packet can be sent out without fragmentation, if so send it out
    if ps_ip4.IP4_HEADER_LEN + len(child_packet.raw_packet) <= stack.mtu:
        ip4_packet_tx = ps_ip4.Ip4Packet(ip4_src=ip4_src, ip4_dst=ip4_dst, ip4_packet_id=self.ip4_packet_id, child_packet=child_packet)

        self.logger.debug(f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
        self.phtx_ether(child_packet=ip4_packet_tx)
        return

    # Fragment packet and send all fragments out
    self.logger.debug("Packet exceedes available MTU, IP fragmentation needed...")

    if child_packet.protocol == "ICMPv4":
        ip4_proto = ps_ip4.IP4_PROTO_ICMP4
        raw_data = child_packet.get_raw_packet()

    if child_packet.protocol in {"UDP", "TCP"}:
        ip4_proto = ps_ip4.IP4_PROTO_UDP if child_packet.protocol == "UDP" else ps_ip4.IP4_PROTO_TCP
        raw_data = child_packet.get_raw_packet(
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(ip4_src),
                socket.inet_aton(ip4_dst),
                0,
                ip4_proto,
                len(child_packet.raw_packet),
            )
        )

    raw_data_mtu = (stack.mtu - ps_ether.ETHER_HEADER_LEN - ps_ip4.IP4_HEADER_LEN) & 0b1111111111111000
    raw_data_fragments = [raw_data[_ : raw_data_mtu + _] for _ in range(0, len(raw_data), raw_data_mtu)]

    pointer = 0
    offset = 0

    for raw_data_fragment in raw_data_fragments:
        ip4_packet_tx = ps_ip4.Ip4Packet(
            ip4_src=ip4_src,
            ip4_dst=ip4_dst,
            ip4_proto=ip4_proto,
            ip4_packet_id=self.ip4_packet_id,
            ip4_flag_mf=pointer < len(raw_data_fragments) - 1,
            ip4_frag_offset=offset,
            raw_data=raw_data_fragment,
            tracker=child_packet.tracker,
        )
        pointer += 1
        offset += len(raw_data_fragment)

        self.logger.debug(f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
        self.phtx_ether(child_packet=ip4_packet_tx)

    return
