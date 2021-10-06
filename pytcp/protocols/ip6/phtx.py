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
# protocols/ip6/phtx.py - packet handler for outbound IPv6 packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Optional, Union

import config
from lib.ip6_address import Ip6Address
from lib.logger import log
from misc.tx_status import TxStatus
from protocols.ip6.fpa import Ip6Assembler
from protocols.raw.fpa import RawAssembler

if TYPE_CHECKING:
    from lib.tracker import Tracker
    from protocols.icmp6.fpa import Icmp6Assembler
    from protocols.ip6_ext_frag.fpa import Ip6ExtFragAssembler
    from protocols.tcp.fpa import TcpAssembler
    from protocols.udp.fpa import UdpAssembler


def _validate_src_ip6_address(self, ip6_src: Ip6Address, ip6_dst: Ip6Address, tracker: Tracker) -> Union[Ip6Address, TxStatus]:
    """Make sure source ip address is valid, supplement with valid one as appropriate"""

    # Check if the the source IP address belongs to this stack or its unspecified
    if ip6_src not in {*self.ip6_unicast, *self.ip6_multicast, Ip6Address(0)}:
        self.packet_stats_tx.ip6__src_not_owned__drop += 1
        if __debug__:
            log("ip6", f"{tracker} - <WARN>Unable to sent out IPv6 packet, stack doesn't own IPv6 address {ip6_src}, dropping</>")
        return TxStatus.DROPED__IP6__SRC_NOT_OWNED

    # If packet is a response to multicast then replace source address with link local address of the stack
    if ip6_src in self.ip6_multicast:
        if self.ip6_unicast:
            self.packet_stats_tx.ip6__src_multicast__replace += 1
            ip6_src = self.ip6_unicast[0]
            if __debug__:
                log("ip6", f"{tracker} - Packet is response to multicast, replaced source with stack link local IPv6 address {ip6_src}")
            return ip6_src
        self.packet_stats_tx.ip6__src_multicast__drop += 1
        if __debug__:
            log("ip6", f"{tracker} - <WARN>Unable to sent out IPv6 packet, no stack link local unicast IPv6 address available</>")
        return TxStatus.DROPED__IP6__SRC_MULTICAST

    # If source is unspecified and destination belongs to any of local networks then pick source address from that network
    if ip6_src.is_unspecified:
        for ip6_host in self.ip6_host:
            if ip6_dst in ip6_host.network:
                self.packet_stats_tx.ip6__src_network_unspecified__replace_local += 1
                ip6_src = ip6_host.address
                if __debug__:
                    log("ip6", f"{tracker} - Packet source is unspecified, replaced source with IPv6 address {ip6_src} from the local destination subnet")
                return ip6_src

    # If source is unspecified and destination is external pick source from first network that has default gateway set
    if ip6_src.is_unspecified:
        for ip6_host in self.ip6_host:
            if ip6_host.gateway:
                self.packet_stats_tx.ip6__src_network_unspecified__replace_external += 1
                ip6_src = ip6_host.address
                if __debug__:
                    log("ip6", f"{tracker} - Packet source is unspecified, replaced source with IPv6 address {ip6_src} that has gateway available")
                return ip6_src

    # If src is unspecified and stack can't replace it
    if ip6_src.is_unspecified:
        self.packet_stats_tx.ip6__src_unspecified__drop += 1
        if __debug__:
            log("ip6", f"{tracker} - <WARN>Packet source is unspecified, unable to replace with valid source, dropping</>")
        return TxStatus.DROPED__IP6__SRC_UNSPECIFIED

    # If nothing above applies return the src address intact
    return ip6_src


def _validate_dst_ip6_address(self, ip6_dst: Ip6Address, tracker) -> Union[Ip6Address, TxStatus]:
    """Make sure destination ip address is valid"""

    # Drop packet if the destination address is unspecified
    if ip6_dst.is_unspecified:
        self.packet_stats_tx.ip6__dst_unspecified__drop += 1
        if __debug__:
            log("ip6", f"{tracker} - <WARN>Destination address is unspecified, dropping</>")
        return TxStatus.DROPED__IP6__DST_UNSPECIFIED

    return ip6_dst


def _phtx_ip6(
    self,
    *,
    ip6_dst: Ip6Address,
    ip6_src: Ip6Address,
    ip6_hop: int = config.IP6_DEFAULT_HOP,
    carried_packet: Optional[Union[Ip6ExtFragAssembler, Icmp6Assembler, TcpAssembler, UdpAssembler, RawAssembler]] = None,
) -> TxStatus:
    """Handle outbound IP packets"""

    if carried_packet is None:
        carried_packet = RawAssembler()

    self.packet_stats_tx.ip6__pre_assemble += 1

    assert 0 < ip6_hop < 256

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not config.IP6_SUPPORT:
        self.packet_stats_tx.ip6__no_proto_support__drop += 1
        return TxStatus.DROPED__IP6__NO_PROTOCOL_SUPPORT

    # Validate source address
    result = self._validate_src_ip6_address(ip6_src, ip6_dst, carried_packet.tracker)
    if isinstance(result, TxStatus):
        return result
    ip6_src = result

    # Validate destination address
    result = self._validate_dst_ip6_address(ip6_dst, carried_packet.tracker)
    if isinstance(result, TxStatus):
        return result
    ip6_dst = result

    # assemble IPv6 apcket
    ip6_packet_tx = Ip6Assembler(src=ip6_src, dst=ip6_dst, hop=ip6_hop, carried_packet=carried_packet)

    # Check if IP packet can be sent out without fragmentation, if so send it out
    if len(ip6_packet_tx) <= config.TAP_MTU:
        self.packet_stats_tx.ip6__mtu_ok__send += 1
        if __debug__:
            log("ip6", f"{ip6_packet_tx.tracker} - {ip6_packet_tx}")
        return self._phtx_ether(carried_packet=ip6_packet_tx)

    # Fragment packet and send out
    self.packet_stats_tx.ip6__mtu_exceed__frag += 1
    if __debug__:
        log("ip6", f"{ip6_packet_tx.tracker} - IPv6 packet len {len(ip6_packet_tx)} bytes, fragmentation needed")
    return self._phtx_ip6_ext_frag(ip6_packet_tx=ip6_packet_tx)
