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
# protocols/icmp6/phrx.py - packet handler for inbound ICMPv6 packets
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING

import misc.stack as stack
from lib.ip6_address import Ip6Address
from lib.logger import log
from protocols.icmp6.fpa import Icmp6NdOptTLLA
from protocols.icmp6.fpp import Icmp6Parser
from protocols.icmp6.ps import (
    ICMP6_ECHO_REPLY,
    ICMP6_ECHO_REQUEST,
    ICMP6_NEIGHBOR_ADVERTISEMENT,
    ICMP6_NEIGHBOR_SOLICITATION,
    ICMP6_ROUTER_ADVERTISEMENT,
    ICMP6_ROUTER_SOLICITATION,
    ICMP6_UNREACHABLE,
)
from protocols.ip6.ps import IP6_HEADER_LEN, IP6_NEXT_HEADER_UDP
from protocols.udp.metadata import UdpMetadata
from protocols.udp.ps import UDP_HEADER_LEN

if TYPE_CHECKING:
    from misc.packet import PacketRx


def _phrx_icmp6(self, packet_rx: PacketRx) -> None:
    """Handle inbound ICMPv6 packets"""

    self.packet_stats_rx.icmp6__pre_parse += 1

    Icmp6Parser(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>")
        self.packet_stats_rx.icmp6__failed_parse__drop += 1
        return

    if __debug__:
        log("icmp6", f"{packet_rx.tracker} - {packet_rx.icmp6}")

    # ICMPv6 Neighbor Solicitation packet
    if packet_rx.icmp6.type == ICMP6_NEIGHBOR_SOLICITATION:
        self.packet_stats_rx.icmp6__neighbor_solicitation += 1
        # Check if request is for one of stack's IPv6 unicast addresses
        if packet_rx.icmp6.ns_target_address not in self.ip6_unicast:
            if __debug__:
                log(
                    "icmp6",
                    f"{packet_rx.tracker} - Received ICMPv6 Neighbor Solicitation packet from {packet_rx.ip6.src}, "
                    + "not matching any of stack's IPv6 unicast addresses, dropping",
                )
            self.packet_stats_rx.icmp6__neighbor_solicitation__unknown__drop += 1
            return

        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - <INFO>Received ICMPv6 Neighbor Solicitation packet from {packet_rx.ip6.src}, sending reply</>")

        # Update ICMPv6 ND cache
        if not (packet_rx.ip6.src.is_unspecified or packet_rx.ip6.src.is_multicast) and packet_rx.icmp6.nd_opt_slla:
            self.packet_stats_rx.icmp6_neighbor_solicitation__update_cache += 1
            self.nd_cache.add_entry(packet_rx.ip6.src, packet_rx.icmp6.nd_opt_slla)

        # Determine if request is part of DAD request by examining its source address
        if ip6_nd_dad := packet_rx.ip6.src.is_unspecified:
            self.packet_stats_rx.icmp6__neighbor_solicitation__nd_dad += 1

        # Send response
        self.packet_stats_rx.icmp6__neighbor_solicitation__self__respond += 1
        self._phtx_icmp6(
            ip6_src=packet_rx.icmp6.ns_target_address,
            ip6_dst=Ip6Address("ff02::1") if ip6_nd_dad else packet_rx.ip6.src,  # use ff02::1 destination addriess when responding to DAD equest
            ip6_hop=255,
            icmp6_type=ICMP6_NEIGHBOR_ADVERTISEMENT,
            icmp6_na_flag_s=not ip6_nd_dad,  # no S flag when responding to DAD request
            icmp6_na_flag_o=ip6_nd_dad,  # O flag when respondidng to DAD request (this is not necessary but Linux uses it)
            icmp6_na_target_address=packet_rx.icmp6.ns_target_address,
            icmp6_nd_options=[Icmp6NdOptTLLA(self.mac_unicast)],
            echo_tracker=packet_rx.tracker,
        )
        return

    # ICMPv6 Neighbor Advertisement packet
    if packet_rx.icmp6.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
        self.packet_stats_rx.icmp6__neighbor_advertisement += 1
        if __debug__:
            log(
                "icmp6", f"{packet_rx.tracker} - Received ICMPv6 Neighbor Advertisement packet for {packet_rx.icmp6.na_target_address} from {packet_rx.ip6.src}"
            )

        # Run ND Duplicate Address Detection check
        if packet_rx.icmp6.na_target_address == self.ip6_unicast_candidate:
            self.packet_stats_rx.icmp6__neighbor_advertisement__run_dad += 1
            self.icmp6_nd_dad_tlla = packet_rx.icmp6.nd_opt_tlla
            self.event_icmp6_nd_dad.release()
            return

        # Update ICMPv6 ND cache
        if packet_rx.icmp6.nd_opt_tlla:
            self.packet_stats_rx.icmp6_neighbor__advertisement__update_cache += 1
            self.nd_cache.add_entry(packet_rx.icmp6.na_target_address, packet_rx.icmp6.nd_opt_tlla)
            return

        return

    # ICMPv6 Router Solicitaion packet (this is not currently used by the stack)
    if packet_rx.icmp6.type == ICMP6_ROUTER_SOLICITATION:
        self.packet_stats_rx.icmp6__router_solicitation += 1
        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - Received ICMPv6 Router Solicitation packet from {packet_rx.ip6.src}")
        return

    # ICMPv6 Router Advertisement packet
    if packet_rx.icmp6.type == ICMP6_ROUTER_ADVERTISEMENT:
        self.packet_stats_rx.icmp6__router_advertisement += 1
        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - Received ICMPv6 Router Advertisement packet from {packet_rx.ip6.src}")
        # Make note of prefixes that can be used for address autoconfiguration
        self.icmp6_ra_prefixes = [(_, packet_rx.ip6.src) for _ in packet_rx.icmp6.nd_opt_pi]
        self.event_icmp6_ra.release()
        return

    # ICMPv6 Echo Request packet
    if packet_rx.icmp6.type == ICMP6_ECHO_REQUEST:
        self.packet_stats_rx.icmp6__echo_request += 1
        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - <INFO>Received ICMPv6 Echo Request packet from {packet_rx.ip6.src}, sending reply</>")

        self._phtx_icmp6(
            ip6_src=packet_rx.ip6.dst,
            ip6_dst=packet_rx.ip6.src,
            ip6_hop=255,
            icmp6_type=ICMP6_ECHO_REPLY,
            icmp6_ec_id=packet_rx.icmp6.ec_id,
            icmp6_ec_seq=packet_rx.icmp6.ec_seq,
            icmp6_ec_data=packet_rx.icmp6.ec_data,
            echo_tracker=packet_rx.tracker,
        )
        return

    # ICMPv6 Unreachable packet
    if packet_rx.icmp6.type == ICMP6_UNREACHABLE:
        self.packet_stats_rx.icmp6__unreachable += 1
        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - Received ICMPv6 Unreachable packet from {packet_rx.ip6.src}, will try to match UDP socket")

        # Quick and dirty way to validate received data and pull useful information from it
        # TODO - This will not work in case of IPv6 extension headers present
        frame = packet_rx.icmp6.un_data
        if len(frame) >= IP6_HEADER_LEN + UDP_HEADER_LEN and frame[0] >> 4 == 6 and frame[6] == IP6_NEXT_HEADER_UDP:
            # Create UdpMetadata object and try to find matching UDP socket
            udp_offset = IP6_HEADER_LEN
            packet = UdpMetadata(
                local_ip_address=Ip6Address(frame[8:24]),
                remote_ip_address=Ip6Address(frame[24:40]),
                local_port=struct.unpack("!H", frame[udp_offset + 0 : udp_offset + 2])[0],
                remote_port=struct.unpack("!H", frame[udp_offset + 2 : udp_offset + 4])[0],
            )

            for socket_pattern in packet.socket_patterns:
                socket = stack.sockets.get(socket_pattern, None)
                if socket:
                    if __debug__:
                        log(
                            "icmp6",
                            f"{packet_rx.tracker} - <INFO>Found matching listening socket {socket} for Unreachable packet from {packet_rx.ip6.src}</>",
                        )
                    socket.notify_unreachable()
                    return

            if __debug__:
                log("icmp6", f"{packet_rx.tracker} - Unreachable data doesn't match any UDP socket")
            return

        if __debug__:
            log("icmp6", f"{packet_rx.tracker} - Unreachable data doesn't pass basic IPv4/UDP integrity check")

        return
