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
# phrx_icmp6.py - packet handler for inbound ICMPv6 packets
#


import ps_icmp6
import stack
from ipv6_address import IPv6Address


def phrx_icmp6(self, ip6_packet_rx, icmp6_packet_rx):
    """ Handle inbound ICMPv6 packets """

    # Validate ICMPv6 packet sanity
    if icmp6_packet_rx.sanity_check_failed:
        return

    self.logger.opt(ansi=True).info(f"<green>{icmp6_packet_rx.tracker}</green> - {icmp6_packet_rx}")

    # ICMPv6 Neighbor Solicitation packet
    if icmp6_packet_rx.icmp6_type == ps_icmp6.ICMP6_NEIGHBOR_SOLICITATION:

        # Check if request is for one of stack's IPv6 unicast addresses
        if icmp6_packet_rx.icmp6_ns_target_address not in self.stack_ip6_unicast:
            self.logger.debug(
                f"Received ICMPv6 Neighbor Solicitation packet from {ip6_packet_rx.ip6_src}, not matching any of stack's IPv6 unicast addresses, droping..."
            )
            return

        self.logger.debug(f"Received ICMPv6 Neighbor Solicitation packet from {ip6_packet_rx.ip6_src}, sending reply")

        # Update ICMPv6 ND cache
        if not (ip6_packet_rx.ip6_src.is_unspecified or ip6_packet_rx.ip6_src.is_multicast) and icmp6_packet_rx.icmp6_nd_opt_slla:
            stack.icmp6_nd_cache.add_entry(ip6_packet_rx.ip6_src, icmp6_packet_rx.icmp6_nd_opt_slla)

        # Determine if request is part of DAD request by examining its source address
        ip6_nd_dad = ip6_packet_rx.ip6_src.is_unspecified

        # Send response
        self.phtx_icmp6(
            ip6_src=icmp6_packet_rx.icmp6_ns_target_address,
            ip6_dst=IPv6Address("ff02::1") if ip6_nd_dad else ip6_packet_rx.ip6_src,  # use ff02::1 destination addriess when responding to DAD equest
            ip6_hop=255,
            icmp6_type=ps_icmp6.ICMP6_NEIGHBOR_ADVERTISEMENT,
            icmp6_na_flag_s=not ip6_nd_dad,  # no S flag when responding to DAD request
            icmp6_na_flag_o=ip6_nd_dad,  # O flag when respondidng to DAD request (this is not neccessary but Linux uses it)
            icmp6_na_target_address=icmp6_packet_rx.icmp6_ns_target_address,
            icmp6_nd_options=[ps_icmp6.Icmp6NdOptTLLA(opt_tlla=self.stack_mac_unicast[0])],
            echo_tracker=icmp6_packet_rx.tracker,
        )
        return

    # ICMPv6 Neighbor Advertisement packet
    if icmp6_packet_rx.icmp6_type == ps_icmp6.ICMP6_NEIGHBOR_ADVERTISEMENT:

        self.logger.debug(f"Received ICMPv6 Neighbor Advertisement packet for {icmp6_packet_rx.icmp6_na_target_address} from {ip6_packet_rx.ip6_src}")

        # Run ND Duplicate Address Detection check
        if icmp6_packet_rx.icmp6_na_target_address == self.ip6_unicast_candidate:
            self.icmp6_nd_dad_tlla = icmp6_packet_rx.icmp6_nd_opt_tlla
            self.event_icmp6_nd_dad.release()
            return

        # Update ICMPv6 ND cache
        if icmp6_packet_rx.icmp6_nd_opt_tlla:
            stack.icmp6_nd_cache.add_entry(icmp6_packet_rx.icmp6_na_target_address, icmp6_packet_rx.icmp6_nd_opt_tlla)
            return

        return

    # ICMPv6 Router Solicitaion packet (this is not currently used by the stack)
    if icmp6_packet_rx.icmp6_type == ps_icmp6.ICMP6_ROUTER_SOLICITATION:

        self.logger.debug(f"Received ICMPv6 Router Advertisement packet from {ip6_packet_rx.ip6_src}")
        return

    # ICMPv6 Router Advertisement packet
    if icmp6_packet_rx.icmp6_type == ps_icmp6.ICMP6_ROUTER_ADVERTISEMENT:

        self.logger.debug(f"Received ICMPv6 Router Advertisement packet from {ip6_packet_rx.ip6_src}")

        # Make note of prefixes that can be used for address autoconfiguration
        self.icmp6_ra_prefixes = [(_, ip6_packet_rx.ip6_src) for _ in icmp6_packet_rx.icmp6_nd_opt_pi]
        self.event_icmp6_ra.release()
        return

    # Respond to ICMPv6 Echo Request packet
    if icmp6_packet_rx.icmp6_type == ps_icmp6.ICMP6_ECHOREQUEST:
        self.logger.debug(f"Received ICMPv6 Echo Request packet from {ip6_packet_rx.ip6_src}, sending reply")

        self.phtx_icmp6(
            ip6_src=ip6_packet_rx.ip6_dst,
            ip6_dst=ip6_packet_rx.ip6_src,
            ip6_hop=255,
            icmp6_type=ps_icmp6.ICMP6_ECHOREPLY,
            icmp6_ec_id=icmp6_packet_rx.icmp6_ec_id,
            icmp6_ec_seq=icmp6_packet_rx.icmp6_ec_seq,
            icmp6_ec_raw_data=icmp6_packet_rx.icmp6_ec_raw_data,
            echo_tracker=icmp6_packet_rx.tracker,
        )
        return
