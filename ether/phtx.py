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


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Union

from ether.fpa import EtherAssembler
from ip4.fpa import Ip4Assembler
from ip6.fpa import Ip6Assembler
from lib.logger import log
from lib.mac_address import MacAddress
from misc.tx_status import TxStatus

if TYPE_CHECKING:
    from arp.fpa import ArpAssembler


def _phtx_ether(
    self,
    carried_packet: Union[ArpAssembler, Ip4Assembler, Ip6Assembler],
    ether_src: MacAddress = MacAddress(0),
    ether_dst: MacAddress = MacAddress(0),
) -> TxStatus:
    """Handle outbound Ethernet packets"""

    def _send_out_packet() -> None:
        if __debug__:
            log("ether", f"{ether_packet_tx.tracker} - {ether_packet_tx}")
        self.tx_ring.enqueue(ether_packet_tx)

    ether_packet_tx = EtherAssembler(src=ether_src, dst=ether_dst, carried_packet=carried_packet)

    # Check if packet contains valid source address, fill it out if needed
    if ether_packet_tx.src.is_unspecified:
        ether_packet_tx.src = self.mac_unicast
        if __debug__:
            log("ether", f"{ether_packet_tx.tracker} - Set source to stack MAC {ether_packet_tx.src}")

    # Send out packet if it contains valid destination MAC address
    if not ether_packet_tx.dst.is_unspecified:
        if __debug__:
            log("ether", f"{ether_packet_tx.tracker} - Contains valid destination MAC address")
        _send_out_packet()
        return TxStatus.PASSED_TO_TX_RING

    # Check if we can obtain destination MAC based on IPv6 header data
    if isinstance(ether_packet_tx._carried_packet, Ip6Assembler):
        ip6_src = ether_packet_tx._carried_packet.src
        ip6_dst = ether_packet_tx._carried_packet.dst

        # Send packet out if its destined to multicast IPv6 address
        if ip6_dst.is_multicast:
            ether_packet_tx.dst = ip6_dst.multicast_mac
            if __debug__:
                log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv6 {ip6_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return TxStatus.PASSED_TO_TX_RING

        # Send out packet if is destined to external network (in relation to its source address) and we are able to obtain MAC of default gateway from ND cache
        for ip6_host in self.ip6_host:
            if ip6_host.address == ip6_src and ip6_dst not in ip6_host.network:
                if ip6_host.gateway is None:
                    if __debug__:
                        log("ether", f"<{ether_packet_tx.tracker} - <WARN>No default gateway set for {ip6_host} source address, dropping</>")
                    return TxStatus.DROPED_ETHER_NO_GATEWAY
                if mac_address := self.nd_cache.find_entry(ip6_host.gateway):
                    ether_packet_tx.dst = mac_address
                    if __debug__:
                        log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv6 {ip6_dst}" + f" to Default Gateway MAC {ether_packet_tx.dst}")
                    _send_out_packet()
                    return TxStatus.PASSED_TO_TX_RING
                return TxStatus.DROPED_ETHER_GATEWAY_CACHE_FAIL

        # Send out packet if we are able to obtain destinaton MAC from ICMPv6 ND cache
        if mac_address := self.nd_cache.find_entry(ip6_dst):
            ether_packet_tx.dst = mac_address
            if __debug__:
                log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv6 {ip6_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return TxStatus.PASSED_TO_TX_RING

    # Check if we can obtain destination MAC based on IPv4 header data
    if isinstance(ether_packet_tx._carried_packet, Ip4Assembler):
        ip4_src = ether_packet_tx._carried_packet.src
        ip4_dst = ether_packet_tx._carried_packet.dst

        # Send out packet if its destinied to limited broadcast addresses
        if ip4_dst.is_limited_broadcast:
            ether_packet_tx.dst = MacAddress(0xFFFFFFFFFFFF)
            if __debug__:
                log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return TxStatus.PASSED_TO_TX_RING

        # Send out packet if its destinied to directed broadcast or network addresses (in relation to its source address)
        for ip4_host in self.ip4_host:
            if ip4_host.address == ip4_src:
                if ip4_dst in {ip4_host.network.address, ip4_host.network.broadcast}:
                    ether_packet_tx.dst = MacAddress(0xFFFFFFFFFFFF)
                    if __debug__:
                        log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst} to MAC {ether_packet_tx.dst}")
                    _send_out_packet()
                    return TxStatus.PASSED_TO_TX_RING

        # Send out packet if is destined to external network (in relation to its source address) and we are able to obtain MAC of default gateway from ARP cache
        for ip4_host in self.ip4_host:
            if ip4_host.address == ip4_src and ip4_dst not in ip4_host.network:
                if ip4_host.gateway is None:
                    if __debug__:
                        log("ether", f"{ether_packet_tx.tracker} - <WARN>No default gateway set for {ip4_host} source address, dropping</>")
                    return TxStatus.DROPED_ETHER_NO_GATEWAY
                if mac_address := self.arp_cache.find_entry(ip4_host.gateway):
                    ether_packet_tx.dst = mac_address
                    if __debug__:
                        log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst}" + f" to Default Gateway MAC {ether_packet_tx.dst}")
                    _send_out_packet()
                    return TxStatus.PASSED_TO_TX_RING
                return TxStatus.DROPED_ETHER_GATEWAY_CACHE_FAIL

        # Send out packet if we are able to obtain destinaton MAC from ARP cache
        if mac_address := self.arp_cache.find_entry(ip4_dst):
            ether_packet_tx.dst = mac_address
            if __debug__:
                log("ether", f"{ether_packet_tx.tracker} - Resolved destination IPv4 {ip4_dst} to MAC {ether_packet_tx.dst}")
            _send_out_packet()
            return TxStatus.PASSED_TO_TX_RING

    # Drop packet in case  we are not able to obtain valid destination MAC address
    if __debug__:
        log("ether", f"{ether_packet_tx.tracker} - <WARN>No valid destination MAC could be obtained, dropping</>")
    return TxStatus.DROPED_ETHER_RESOLUTION_FAIL
