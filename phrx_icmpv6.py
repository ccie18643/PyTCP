#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_icmpv6.py - packet handler for inbound ICMPv6 packets

"""

import ps_icmpv6

import stack


def phrx_icmpv6(self, ipv6_packet_rx, icmpv6_packet_rx):
    """ Handle inbound ICMPv6 packets """

    self.logger.opt(ansi=True).info(f"<green>{icmpv6_packet_rx.tracker}</green> - {icmpv6_packet_rx}")

    # Validate ICMPv6 packet checksum
    if not icmpv6_packet_rx.validate_cksum(ipv6_packet_rx.ipv6_pseudo_header):
        self.logger.debug(f"{icmpv6_packet_rx.tracker} - ICMPv6 packet has invalid checksum, droping")
        return

    # Respond to ICMPv6 Neighbor Solicitation packet if querry is for one of ours unicast IPv6 addresses (also update ND cache)
    if icmpv6_packet_rx.icmpv6_type == ps_icmpv6.ICMPV6_NEIGHBOR_SOLICITATION and icmpv6_packet_rx.icmpv6_code == 0:

        if icmpv6_packet_rx.icmpv6_nd_target_address not in self.stack_ipv6_unicast:
            self.logger.debug(
                f"Received ICMPv6 Neighbor Solicitation packet from {ipv6_packet_rx.ipv6_src}, not matching any of stack's IPv6 unicast addressesi, droping"
            )
            return

        if ipv6_packet_rx.ipv6_hop != 255:
            self.logger.debug(
                f"Received ICMPv6 Neighbor Solicitation packet from {ipv6_packet_rx.ipv6_src}, wrong hop limit value {ipv6_packet_rx.ipv6_hop}, droping"
            )
            return

        self.logger.debug(f"Received ICMPv6 Neighbor Solicitation packet from {ipv6_packet_rx.ipv6_src}, sending reply")

        if not (ipv6_packet_rx.ipv6_src.is_unspecified or ipv6_packet_rx.ipv6_src.is_multicast) and icmpv6_packet_rx.icmpv6_nd_opt_slla:
            stack.icmpv6_nd_cache.add_entry(ipv6_packet_rx.ipv6_src, icmpv6_packet_rx.icmpv6_nd_opt_slla)

        self.phtx_icmpv6(
            ipv6_src=icmpv6_packet_rx.icmpv6_nd_target_address,
            ipv6_dst=ipv6_packet_rx.ipv6_src,
            icmpv6_type=ps_icmpv6.ICMPV6_NEIGHBOR_ADVERTISEMENT,
            icmpv6_nd_flag_s=True,
            icmpv6_nd_flag_o=True,
            icmpv6_nd_target_address=icmpv6_packet_rx.icmpv6_nd_target_address,
            icmpv6_nd_options=[ps_icmpv6.ICMPv6NdOptTLLA(opt_tlla=self.stack_mac_unicast[0])],
            echo_tracker=icmpv6_packet_rx.tracker,
        )

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
