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


import config
import fpa_ip4
from ipv4_address import IPv4Address


def validate_src_ip4_address(self, ip4_src, ip4_dst):
    """ Make sure source ip address is valid, supplemt with valid one as appropriate """

    # Check if the the source IP address belongs to this stack or its set to all zeros (for DHCP client communication)
    if ip4_src not in {*self.ip4_unicast, *self.ip4_multicast, *self.ip4_broadcast, IPv4Address("0.0.0.0")}:
        if __debug__:
            self._logger.warning(f"Unable to sent out IPv4 packet, stack doesn't own IPv4 address {ip4_src}")
        return None

    # If packet is a response to multicast then replace source address with primary address of the stack
    if ip4_src in self.ip4_multicast:
        if self.ip4_unicast:
            ip4_src = self.ip4_unicast[0]
            if __debug__:
                self._logger.debug(f"Packet is response to multicast, replaced source with stack primary IPv4 address {ip4_src}")
        else:
            if __debug__:
                self._logger.warning("Unable to sent out IPv4 packet, no stack primary unicast IPv4 address available")
            return None

    # If packet is a response to limited broadcast then replace source address with primary address of the stack
    if ip4_src.is_limited_broadcast:
        if self.ip4_unicast:
            ip4_src = self.ip4_unicast[0]
            if __debug__:
                self._logger.debug(f"Packet is response to limited broadcast, replaced source with stack primary IPv4 address {ip4_src}")
        else:
            if __debug__:
                self._logger.warning("Unable to sent out IPv4 packet, no stack primary unicast IPv4 address available")
            return None

    # If packet is a response to directed braodcast then replace source address with first stack address that belongs to appropriate subnet
    if ip4_src in self.ip4_broadcast:
        ip4_src = [_.ip for _ in self.ip4_address if _.broadcast_address == ip4_src]
        if ip4_src:
            ip4_src = ip4_src[0]
            if __debug__:
                self._logger.debug(f"Packet is response to directed broadcast, replaced source with appropriate IPv4 address {ip4_src}")
        else:
            if __debug__:
                self._logger.warning("Unable to sent out IPv4 packet, no appropriate stack unicast IPv4 address available")
            return None

    # If source is unspecified check if destination belongs to any of local networks, if so pick source address from that network
    if ip4_src.is_unspecified:
        for ip4_address in self.ip4_address:
            if ip4_dst in ip4_address.network:
                return ip4_address.ip

    # If source unspcified and destination is external pick source from first network that has default gateway set
    if ip4_src.is_unspecified:
        for ip4_address in self.ip4_address:
            if ip4_address.gateway:
                return ip4_address.ip

    return ip4_src


def validate_dst_ip4_address(self, ip4_dst):
    """ Make sure destination ip address is valid """

    # Drop packet if the destination address is unspecified
    if ip4_dst.is_unspecified:
        if __debug__:
            self._logger.warning("Destination address is unspecified, dropping...")
        return None

    return ip4_dst


def _phtx_ip4(self, child_packet, ip4_dst, ip4_src, ip4_ttl=config.ip4_default_ttl):
    """ Handle outbound IP packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not config.ip4_support:
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

    # Assemble IPv4 packet
    ip4_packet_tx = fpa_ip4.Ip4Packet(src=ip4_src, dst=ip4_dst, ttl=ip4_ttl, child_packet=child_packet)

    # Send packet out if it's size doesn't exceed mtu
    if len(ip4_packet_tx) <= config.mtu:
        if __debug__:
            self._logger.debug(f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
        self._phtx_ether(child_packet=ip4_packet_tx)
        return

    # Fragment packet and send out
    if __debug__:
        self._logger.debug(f"{ip4_packet_tx.tracker} - IPv4 packet len {len(ip4_packet_tx)} bytes, fragmentation needed")
        data = bytearray(ip4_packet_tx.dlen)
        ip4_packet_tx._child_packet.assemble_packet(data, 0, ip4_packet_tx.pshdr_sum)
        data_mtu = (config.mtu - ip4_packet_tx.hlen) & 0b1111111111111000
        data_frags = [data[_ : data_mtu + _] for _ in range(0, len(data), data_mtu)]
        offset = 0
        self.ip4_id += 1
        for data_frag in data_frags:
            ip4_frag_tx = fpa_ip4.Ip4Frag(
                src=ip4_src,
                dst=ip4_dst,
                ttl=ip4_ttl,
                data=data_frag,
                offset=offset,
                flag_mf=data_frag is not data_frags[-1],
                id=self.ip4_id,
                proto=ip4_packet_tx.proto,
            )
            if __debug__:
                self._logger.debug(f"{ip4_frag_tx.tracker} - {ip4_frag_tx}")
            offset += len(data_frag)
            self._phtx_ether(child_packet=ip4_frag_tx)
        return
