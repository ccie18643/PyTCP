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
# protocols/ip4/phtx.py - packet handler for outbound IPv4 packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Optional, Union

import config
from lib.ip4_address import Ip4Address
from lib.logger import log
from misc.ip_helper import pick_local_ip4_address
from misc.tx_status import TxStatus
from protocols.ip4.fpa import Ip4Assembler, Ip4FragAssembler

if TYPE_CHECKING:
    from lib.tracker import Tracker
    from protocols.icmp4.fpa import Icmp4Assembler
    from protocols.tcp.fpa import TcpAssembler
    from protocols.udp.fpa import UdpAssembler


def _validate_src_ip4_address(self, ip4_src: Ip4Address, ip4_dst: Ip4Address, tracker: Tracker) -> Optional[Ip4Address]:
    """Make sure source ip address is valid, supplemt with valid one as appropriate"""

    # Check if the the source IP address belongs to this stack or its set to all zeros (for DHCP client communication)
    if ip4_src not in {*self.ip4_unicast, *self.ip4_multicast, *self.ip4_broadcast, Ip4Address(0)}:
        if __debug__:
            log("ip4", f"{tracker} - <WARN>Unable to sent out IPv4 packet, stack doesn't own IPv4 address {ip4_src}, dropping</>")
        return None

    # If packet is a response to multicast then replace source address with primary address of the stack
    if ip4_src in self.ip4_multicast:
        if self.ip4_unicast:
            ip4_src = self.ip4_unicast[0]
            if __debug__:
                log("ip4", f"{tracker} - Packet is response to multicast, replaced source with stack primary IPv4 address {ip4_src}")
        else:
            if __debug__:
                log("ip4", f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack primary unicast IPv4 address available, dropping</>")
            return None

    # If packet is a response to limited broadcast then replace source address with primary address of the stack
    if ip4_src.is_limited_broadcast:
        if self.ip4_unicast:
            ip4_src = self.ip4_unicast[0]
            if __debug__:
                log("ip4", f"{tracker} - Packet is response to limited broadcast, replaced source with stack primary IPv4 address {ip4_src}")
        else:
            if __debug__:
                log("ip4", f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack primary unicast IPv4 address available, dropping</>")
            return None

    # If packet is a response to directed braodcast then replace source address with first stack address that belongs to appropriate subnet
    if ip4_src in self.ip4_broadcast:
        ip4_src_list = [_.address for _ in self.ip4_host if _.network.broadcast == ip4_src]
        if ip4_src_list:
            ip4_src = ip4_src_list[0]
            if __debug__:
                log("ip4", f"{tracker} - Packet is response to directed broadcast, replaced source with appropriate IPv4 address {ip4_src}")
        else:
            if __debug__:
                log("ip4", f"{tracker} - <WARN>Unable to sent out IPv4 packet, no appropriate stack unicast IPv4 address available, dropping</>")
            return None

    # If source is unspecified try to find best match for given destination
    if ip4_src.is_unspecified:
        return pick_local_ip4_address(ip4_dst)

    return ip4_src


def _validate_dst_ip4_address(self, ip4_dst: Ip4Address, tracker) -> Optional[Ip4Address]:
    """Make sure destination ip address is valid"""

    # Drop packet if the destination address is unspecified
    if ip4_dst.is_unspecified:
        if __debug__:
            log("ip4", f"{tracker} - <WARN>Destination address is unspecified, dropping</>")
        return None

    return ip4_dst


def _phtx_ip4(
    self,
    carried_packet: Union[Icmp4Assembler, TcpAssembler, UdpAssembler],
    ip4_dst: Ip4Address,
    ip4_src: Ip4Address,
    ip4_ttl: int = config.IP4_DEFAULT_TTL,
) -> TxStatus:
    """Handle outbound IP packets"""

    self.packet_stats_tx.ip4__pre_assemble += 1

    assert 0 < ip4_ttl < 256

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not config.IP4_SUPPORT:
        self.packet_stats_tx.ip4__no_proto_support__drop += 1
        return TxStatus.DROPED_IP4_NO_PROTOCOL_SUPPORT

    # Validate source address
    ip4_src = self._validate_src_ip4_address(ip4_src, ip4_dst, carried_packet.tracker)
    if not ip4_src:
        self.packet_stats_tx.ip4__src_invalid__drop += 1
        return TxStatus.DROPED_IP4_INVALID_SOURCE

    # Validate destination address
    ip4_dst = self._validate_dst_ip4_address(ip4_dst, carried_packet.tracker)
    if not ip4_dst:
        self.packet_stats_tx.ip4__dst_invalid__drop += 1
        return TxStatus.DROPED_IP4_INVALID_DESTINATION

    # Assemble IPv4 packet
    ip4_packet_tx = Ip4Assembler(src=ip4_src, dst=ip4_dst, ttl=ip4_ttl, carried_packet=carried_packet)

    # Send packet out if it's size doesn't exceed mtu
    if len(ip4_packet_tx) <= config.TAP_MTU:
        self.packet_stats_tx.ip4__mtu_ok__send += 1
        if __debug__:
            log("ip4", f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
        return self._phtx_ether(carried_packet=ip4_packet_tx)

    # Fragment packet and send out
    self.packet_stats_tx.ip4__mtu_exceed__frag += 1
    if __debug__:
        log("ip4", f"{ip4_packet_tx.tracker} - IPv4 packet len {len(ip4_packet_tx)} bytes, fragmentation needed")
    data = memoryview(bytearray(ip4_packet_tx.dlen))
    ip4_packet_tx._carried_packet.assemble(data, ip4_packet_tx.pshdr_sum)
    data_mtu = (config.TAP_MTU - ip4_packet_tx.hlen) & 0b1111111111111000
    data_frags = [data[_ : data_mtu + _] for _ in range(0, len(data), data_mtu)]
    offset = 0
    self.ip4_id += 1
    ether_tx_status: set[TxStatus] = set()
    for data_frag in data_frags:
        ip4_frag_tx = Ip4FragAssembler(
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
            log("ip4", f"{ip4_frag_tx.tracker} - {ip4_frag_tx}")
        offset += len(data_frag)
        self.packet_stats_tx.ip4__mtu_exceed__frag__send += 1
        ether_tx_status.add(self._phtx_ether(carried_packet=ip4_frag_tx))

    # Return the most severe code
    for tx_status in [
        TxStatus.DROPED_ETHER_RESOLUTION_FAIL,
        TxStatus.DROPED_ETHER_NO_GATEWAY,
        TxStatus.DROPED_ETHER_CACHE_FAIL,
        TxStatus.DROPED_ETHER_GATEWAY_CACHE_FAIL,
        TxStatus.PASSED_TO_TX_RING,
    ]:
        if tx_status in ether_tx_status:
            return tx_status

    return TxStatus.DROPED_IP4_UNKNOWN
