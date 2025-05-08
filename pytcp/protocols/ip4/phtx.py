#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable = expression-not-assigned
# pylint: disable = too-many-branches
# pylint: disable = too-many-return-statements
# pylint: disable = protected-access

"""
Module contains packet handler for the outbound IPv4 packets.

pytcp/protocols/ip4/phtx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp4.fpa import Icmp4Assembler
from pytcp.protocols.ip4.fpa import Ip4Assembler, Ip4FragAssembler
from pytcp.protocols.raw.fpa import RawAssembler
from pytcp.protocols.udp.fpa import UdpAssembler

if TYPE_CHECKING:
    from pytcp.lib.tracker import Tracker
    from pytcp.protocols.tcp.fpa import TcpAssembler
    from pytcp.subsystems.packet_handler import PacketHandler


def _validate_src_ip4_address(
    self: PacketHandler,
    ip4_src: Ip4Address,
    ip4_dst: Ip4Address,
    carried_packet: (
        Icmp4Assembler
        | TcpAssembler
        | UdpAssembler
        | Ip4FragAssembler
        | RawAssembler
    ),
) -> Ip4Address | TxStatus:
    """
    Make sure source ip address is valid, supplement with valid one
    as appropriate.
    """

    tracker = carried_packet.tracker

    # Check if the the source IP address belongs to this stack or is set to all
    # zeros (for DHCP client communication).
    if ip4_src not in {
        *self.ip4_unicast,
        *self.ip4_multicast,
        *self.ip4_broadcast,
        Ip4Address(0),
    }:
        self.packet_stats_tx.ip4__src_not_owned__drop += 1
        __debug__ and log(
            "ip4",
            f"{tracker} - <WARN>Unable to sent out IPv4 packet, stack "
            f"doesn't own IPv4 address {ip4_src}, dropping</>",
        )
        return TxStatus.DROPED__IP4__SRC_NOT_OWNED

    # If packet is a response to multicast then replace source address with
    # primary address of the stack
    if ip4_src in self.ip4_multicast:
        if self.ip4_unicast:
            self.packet_stats_tx.ip4__src_multicast__replace += 1
            ip4_src = self.ip4_unicast[0]
            __debug__ and log(
                "ip4",
                f"{tracker} - Packet is response to multicast, replaced "
                f"source with stack primary IPv4 address {ip4_src}",
            )
            return ip4_src
        self.packet_stats_tx.ip4__src_multicast__drop += 1
        __debug__ and log(
            "ip4",
            f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
            f"primary unicast IPv4 address available, dropping</>",
        )
        return TxStatus.DROPED__IP4__SRC_MULTICAST

    # If packet is a response to limited broadcast then replace source address
    # with primary address of the stack
    if ip4_src.is_limited_broadcast:
        if self.ip4_unicast:
            self.packet_stats_tx.ip4__src_limited_broadcast__replace += 1
            ip4_src = self.ip4_unicast[0]
            __debug__ and log(
                "ip4",
                f"{tracker} - Packet is response to limited broadcast, "
                "replaced source with stack primary IPv4 "
                f"address {ip4_src}",
            )
            return ip4_src
        self.packet_stats_tx.ip4__src_limited_broadcast__drop += 1
        __debug__ and log(
            "ip4",
            f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
            f"primary unicast IPv4 address available, dropping</>",
        )
        return TxStatus.DROPED__IP4__SRC_LIMITED_BROADCAST

    # If packet is a response to network broadcast then replace source address
    # with first stack address that belongs to appropriate subnet
    if ip4_src in self.ip4_broadcast:
        ip4_src_list = [
            _.address for _ in self.ip4_host if _.network.broadcast == ip4_src
        ]
        if ip4_src_list:
            self.packet_stats_tx.ip4__src_network_broadcast__replace += 1
            ip4_src = ip4_src_list[0]
            __debug__ and log(
                "ip4",
                f"{tracker} - Packet is response to network broadcast, "
                f"replaced source with appropriate IPv4 address {ip4_src}",
            )
            return ip4_src

    # If source is unspecified and destination belongs to any of local networks
    # then pick source address from that network.
    if ip4_src.is_unspecified:
        for ip4_host in self.ip4_host:
            if ip4_dst in ip4_host.network:
                self.packet_stats_tx.ip4__src_network_unspecified__replace_local += (
                    1
                )
                ip4_src = ip4_host.address
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet source is unspecified, replaced "
                    f"source with IPv4 address {ip4_src} from the local "
                    "destination subnet",
                )
                return ip4_src

    # If source is unspecified and destination is external pick source from
    # first network that has default gateway set.
    if ip4_src.is_unspecified:
        for ip4_host in self.ip4_host:
            if ip4_host.gateway:
                self.packet_stats_tx.ip4__src_network_unspecified__replace_external += (
                    1
                )
                ip4_src = ip4_host.address
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet source is unspecified, replaced "
                    f"source with IPv4 address {ip4_src} that has gateway "
                    "available",
                )
                return ip4_src

    # If src is unspecified and stack is sending DHCP packet
    if (
        ip4_src.is_unspecified
        and isinstance(carried_packet, UdpAssembler)
        and carried_packet._sport == 68
        and carried_packet._dport == 67
    ):
        self.packet_stats_tx.ip4__src_unspecified__send += 1
        __debug__ and log(
            "ip4",
            f"{tracker} - Packet source is unspecified, DHCPv4 packet, "
            "sending",
        )
        return ip4_src

    # If src is unspecified and stack can't replace it
    if ip4_src.is_unspecified:
        self.packet_stats_tx.ip4__src_unspecified__drop += 1
        __debug__ and log(
            "ip4",
            f"{tracker} - <WARN>Packet source is unspecified, unable to "
            "replace with valid source, dropping</>",
        )
        return TxStatus.DROPED__IP4__SRC_UNSPECIFIED

    # If nothing above applies return the src address intact
    return ip4_src


def _validate_dst_ip4_address(
    self: PacketHandler, ip4_dst: Ip4Address, tracker: Tracker
) -> Ip4Address | TxStatus:
    """Make sure destination ip address is valid"""

    # Drop packet if the destination address is unspecified
    if ip4_dst.is_unspecified:
        self.packet_stats_tx.ip4__dst_unspecified__drop += 1
        __debug__ and log(
            "ip4",
            f"{tracker} - <WARN>Destination address is unspecified, "
            "dropping</>",
        )
        return TxStatus.DROPED__IP4__DST_UNSPECIFIED

    return ip4_dst


def _phtx_ip4(
    self: PacketHandler,
    *,
    ip4_dst: Ip4Address,
    ip4_src: Ip4Address,
    ip4_ttl: int = config.IP4_DEFAULT_TTL,
    carried_packet: (
        Icmp4Assembler | TcpAssembler | UdpAssembler | RawAssembler | None
    ) = None,
) -> TxStatus:
    """Handle outbound IP packets"""

    if carried_packet is None:
        carried_packet = RawAssembler()

    self.packet_stats_tx.ip4__pre_assemble += 1

    assert 0 < ip4_ttl < 256

    # Check if IPv4 protocol support is enabled, if not then silently drop
    # the packet
    if not config.IP4_SUPPORT:
        self.packet_stats_tx.ip4__no_proto_support__drop += 1
        return TxStatus.DROPED__IP4__NO_PROTOCOL_SUPPORT

    # Validate source address
    result = self._validate_src_ip4_address(ip4_src, ip4_dst, carried_packet)
    if isinstance(result, TxStatus):
        return result
    ip4_src = result

    # Validate destination address
    result = self._validate_dst_ip4_address(ip4_dst, carried_packet.tracker)
    if isinstance(result, TxStatus):
        return result
    ip4_dst = result

    # Assemble IPv4 packet
    ip4_packet_tx = Ip4Assembler(
        src=ip4_src, dst=ip4_dst, ttl=ip4_ttl, carried_packet=carried_packet
    )

    # Send packet out if it's size doesn't exceed mtu
    if len(ip4_packet_tx) <= config.TAP_MTU:
        self.packet_stats_tx.ip4__mtu_ok__send += 1
        __debug__ and log("ip4", f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
        return self._phtx_ether(carried_packet=ip4_packet_tx)

    # Fragment packet and send out
    self.packet_stats_tx.ip4__mtu_exceed__frag += 1
    __debug__ and log(
        "ip4",
        f"{ip4_packet_tx.tracker} - IPv4 packet len {len(ip4_packet_tx)} "
        "bytes, fragmentation needed",
    )
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
        __debug__ and log("ip4", f"{ip4_frag_tx.tracker} - {ip4_frag_tx}")
        offset += len(data_frag)
        self.packet_stats_tx.ip4__mtu_exceed__frag__send += 1
        ether_tx_status.add(self._phtx_ether(carried_packet=ip4_frag_tx))

    # Return the most severe code
    for tx_status in [
        TxStatus.DROPED__ETHER__DST_RESOLUTION_FAIL,
        TxStatus.DROPED__ETHER__DST_NO_GATEWAY_IP4,
        TxStatus.DROPED__ETHER__DST_ARP_CACHE_FAIL,
        TxStatus.DROPED__ETHER__DST_GATEWAY_ARP_CACHE_FAIL,
        TxStatus.PASSED__ETHER__TO_TX_RING,
    ]:
        if tx_status in ether_tx_status:
            return tx_status

    return TxStatus.DROPED__IP4__UNKNOWN
