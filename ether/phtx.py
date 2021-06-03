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


#
# ether/phtx.py - packet handler for outbound Ethernet packets
#

from typing import Union, cast

import arp.fpa
import ether.fpa
import ether.ps
import ip4.fpa
import ip6.fpa


def _phtx_ether(
    self, carried_packet: Union[arp.fpa.Assembler, ip4.fpa.Assembler, ip6.fpa.Assembler], ether_src="00:00:00:00:00:00", ether_dst="00:00:00:00:00:00"
) -> None:
    """Handle outbound Ethernet packets"""

    def _send_out_packet() -> None:
        if __debug__:
            self._logger.opt(depth=1).debug(f"{ether_packet_tx.tracker} - {ether_packet_tx}")
        self.tx_ring.enqueue(ether_packet_tx)

    ether_packet_tx = ether.fpa.Assembler(src=ether_src, dst=ether_dst, carried_packet=carried_packet)

    # Check if packet contains valid source address, fill it out if needed
    if ether_packet_tx.src == "00:00:00:00:00:00":
        ether_packet_tx.src = self.mac_unicast
        if __debug__:
            self._logger.debug(f"{ether_packet_tx.tracker} - Set source to stack MAC {ether_packet_tx.src}")

    # Send out packet if it contains valid destination MAC address
    if ether_packet_tx.dst != "00:00:00:00:00:00":
        if __debug__:
            self._logger.debug(f"{ether_packet_tx.tracker} - Contains valid destination MAC address")
        _send_out_packet()
        return

    # Check if we can obtain destination MAC based on IPv6 header data
    if ether_packet_tx.type == ether.ps.TYPE_IP6:
        ether_packet_tx._carried_packet = cast(ip6.fpa.Assembler, ether_packet_tx._carried_packet)
        ip6_src = ether_packet_tx._carried_packet.src
        ip6_dst = ether_packet_tx._carried_packet.dst

        # Send packet out if its destined to multicast IPv6 address
        if ip6_dst.is_multicast:
            ether_packet_tx.dst = ip6_dst.multicast_mac
            if __debug__:
                self._logger.debug(f"{ether_packet_tx.tracker} - Resolved destination IPv6 {ip6_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return

        # Send out packet if is destined to external network (in relation to its source address) and we are able to obtain MAC of default gateway from ND cache
        for stack_ip6_address in self.ip6_address:
            if stack_ip6_address.ip == ip6_src and ip6_dst not in stack_ip6_address.network:
                if stack_ip6_address.gateway is None:
                    if __debug__:
                        self._logger.debug(f"{ether_packet_tx.tracker} - No default gateway set for {stack_ip6_address} source address, dropping packet...")
                    return
                if mac_address := self.icmp6_nd_cache.find_entry(stack_ip6_address.gateway):
                    ether_packet_tx.dst = mac_address
                    if __debug__:
                        self._logger.debug(
                            f"{ether_packet_tx.tracker} - Resolved destination IPv6 {ip6_dst}" + f" to Default Gateway MAC {ether_packet_tx.dst}"
                        )
                    _send_out_packet()
                    return

        # Send out packet if we are able to obtain destinaton MAC from ICMPv6 ND cache
        if mac_address := self.icmp6_nd_cache.find_entry(ip6_dst):
            ether_packet_tx.dst = mac_address
            if __debug__:
                self._logger.debug(f"{ether_packet_tx.tracker} - Resolved destination IPv6 {ip6_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return

    # Check if we can obtain destination MAC based on IPv4 header data
    if ether_packet_tx.type == ether.ps.TYPE_IP4:
        ether_packet_tx._carried_packet = cast(ip4.fpa.Assembler, ether_packet_tx._carried_packet)
        ip4_src = ether_packet_tx._carried_packet.src
        ip4_dst = ether_packet_tx._carried_packet.dst

        # Send out packet if its destinied to limited broadcast addresses
        if ip4_dst.is_limited_broadcast:
            ether_packet_tx.dst = "ff:ff:ff:ff:ff:ff"
            if __debug__:
                self._logger.debug(f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return

        # Send out packet if its destinied to directed broadcast or network addresses (in relation to its source address)
        for ip4_address in self.ip4_address:
            if ip4_address.ip == ip4_src:
                if ip4_dst in {ip4_address.network_address, ip4_address.broadcast_address}:
                    ether_packet_tx.dst = "ff:ff:ff:ff:ff:ff"
                    if __debug__:
                        self._logger.debug(f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst} to MAC {ether_packet_tx.dst}")
                    _send_out_packet()
                    return

        # Send out packet if is destined to external network (in relation to its source address) and we are able to obtain MAC of default gateway from ARP cache
        for stack_ip4_address in self.ip4_address:
            if stack_ip4_address.ip == ip4_src and ip4_dst not in stack_ip4_address.network:
                if stack_ip4_address.gateway is None:
                    if __debug__:
                        self._logger.debug(f"{ether_packet_tx.tracker} - No default gateway set for {stack_ip4_address} source address, dropping packet...")
                    return
                if mac_address := self.arp_cache.find_entry(stack_ip4_address.gateway):
                    ether_packet_tx.dst = mac_address
                    if __debug__:
                        self._logger.debug(
                            f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst}" + f" to Default Gateway MAC {ether_packet_tx.dst}"
                        )
                    _send_out_packet()
                    return

        # Send out packet if we are able to obtain destinaton MAC from ARP cache
        if mac_address := self.arp_cache.find_entry(ip4_dst):
            ether_packet_tx.dst = mac_address
            if __debug__:
                self._logger.debug(f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return

    # Drop packet in case  we are not able to obtain valid destination MAC address
    if __debug__:
        self._logger.debug(f"{ether_packet_tx.tracker} - No valid destination MAC could be obtained, dropping packet...")
    return
