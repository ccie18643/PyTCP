#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_icmpv6.py - packet handler for inbound ICMPv6 packets

"""

from ipaddress import IPv6Address

import ps_icmpv6

import stack


def phrx_icmpv6(self, ipv6_packet_rx, icmpv6_packet_rx):
    """ Handle inbound ICMPv6 packets """

    self.logger.opt(ansi=True).info(f"<green>{icmpv6_packet_rx.tracker}</green> - {icmpv6_packet_rx}")

    # Validate ICMPv6 packet checksum
    if not icmpv6_packet_rx.validate_cksum(ipv6_packet_rx.ip_pseudo_header):
        self.logger.debug(f"{icmpv6_packet_rx.tracker} - ICMPv6 packet has invalid checksum, droping")
        return

    # ICMPv6 Neighbor Solicitation packet
    if icmpv6_packet_rx.icmpv6_type == ps_icmpv6.ICMPV6_NEIGHBOR_SOLICITATION and icmpv6_packet_rx.icmpv6_code == 0:

        # Check if request is for one of stack's IPv6 unicast addresses
        if icmpv6_packet_rx.icmpv6_nd_target_address not in self.stack_ipv6_unicast:
            self.logger.debug(
                f"Received ICMPv6 Neighbor Solicitation packet from {ipv6_packet_rx.ipv6_src}, not matching any of stack's IPv6 unicast addresses, droping"
            )
            return

        # Sanity check on packets hop limit field, this must be set to 255
        if ipv6_packet_rx.ipv6_hop != 255:
            self.logger.debug(
                f"Received ICMPv6 Neighbor Solicitation packet from {ipv6_packet_rx.ipv6_src}, wrong hop limit value {ipv6_packet_rx.ipv6_hop}, droping"
            )
            return

        self.logger.debug(f"Received ICMPv6 Neighbor Solicitation packet from {ipv6_packet_rx.ipv6_src}, sending reply")

        # Update ICMPv6 ND cache
        if not (ipv6_packet_rx.ipv6_src.is_unspecified or ipv6_packet_rx.ipv6_src.is_multicast) and icmpv6_packet_rx.icmpv6_nd_opt_slla:
            stack.icmpv6_nd_cache.add_entry(ipv6_packet_rx.ipv6_src, icmpv6_packet_rx.icmpv6_nd_opt_slla)

        # Send response (for ND DAD to work the S flag must not be set)
        self.phtx_icmpv6(
            ipv6_src=icmpv6_packet_rx.icmpv6_nd_target_address,
            ipv6_dst=ipv6_packet_rx.ipv6_src,
            icmpv6_type=ps_icmpv6.ICMPV6_NEIGHBOR_ADVERTISEMENT,
            icmpv6_nd_flag_s=False if ipv6_packet_rx.ipv6_src == IPv6Address("::") else True,
            icmpv6_nd_flag_o=False,
            icmpv6_nd_target_address=icmpv6_packet_rx.icmpv6_nd_target_address,
            icmpv6_nd_options=[ps_icmpv6.ICMPv6NdOptTLLA(opt_tlla=self.stack_mac_unicast[0])],
            echo_tracker=icmpv6_packet_rx.tracker,
        )

        return

    # ICMPv6 Neighbor Advertisement packet
    if icmpv6_packet_rx.icmpv6_type == ps_icmpv6.ICMPV6_NEIGHBOR_ADVERTISEMENT and icmpv6_packet_rx.icmpv6_code == 0:

        # Sanity check on packets hop limit field, this must be set to 255
        if ipv6_packet_rx.ipv6_hop != 255:
            self.logger.debug(
                f"Received ICMPv6 Neighbor Advertisement packet from {ipv6_packet_rx.ipv6_src}, wrong hop limit value {ipv6_packet_rx.ipv6_hop}, droping"
            )
            return

        self.logger.debug(f"Received ICMPv6 Neighbor Advertisement packet for {icmpv6_packet_rx.icmpv6_nd_target_address} from {ipv6_packet_rx.ipv6_src}")

        # Run ND Duplicate Address Detection check
        if icmpv6_packet_rx.icmpv6_nd_target_address == self.ipv6_unicast_candidate:
            self.icmpv6_nd_dad_tlla = icmpv6_packet_rx.icmpv6_nd_opt_tlla
            self.event_icmpv6_nd_dad.release()
            return

        # Update ICMPv6 ND cache
        if icmpv6_packet_rx.icmpv6_nd_opt_tlla:
            stack.icmpv6_nd_cache.add_entry(icmpv6_packet_rx.icmpv6_nd_target_address, icmpv6_packet_rx.icmpv6_nd_opt_tlla)
            return

    # Respond to ICMPv6 Echo Request packet
    if icmpv6_packet_rx.icmpv6_type == ps_icmpv6.ICMPV6_ECHOREQUEST and icmpv6_packet_rx.icmpv6_code == 0:
        self.logger.debug(f"Received ICMPv6 Echo Request packet from {ipv6_packet_rx.ipv6_src}, sending reply")

        self.phtx_icmpv6(
            ipv6_src=ipv6_packet_rx.ipv6_dst,
            ipv6_dst=ipv6_packet_rx.ipv6_src,
            icmpv6_type=ps_icmpv6.ICMPV6_ECHOREPLY,
            icmpv6_id=icmpv6_packet_rx.icmpv6_id,
            icmpv6_seq=icmpv6_packet_rx.icmpv6_seq,
            icmpv6_raw_data=icmpv6_packet_rx.icmpv6_raw_data,
            echo_tracker=icmpv6_packet_rx.tracker,
        )
        return
