#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_icmpv6.py - packet handler for inbound ICMPv6 packets

"""

import ps_icmpv6


def phrx_icmpv6(self, ipv6_packet_rx, icmpv6_packet_rx):
    """ Handle inbound ICMPv6 packets """

    self.logger.opt(ansi=True).info(f"<green>{icmpv6_packet_rx.tracker}</green> - {icmpv6_packet_rx}")

    # Validate ICMPv6 packet checksum
    if not icmpv6_packet_rx.validate_cksum(ipv6_packet_rx.ipv6_pseudo_header):
        self.logger.debug(f"{icmpv6_packet_rx.tracker} - ICMPv6 packet has invalid checksum, droping")
        return

    # Respond to ICMPv6 Echo Request packet
    if icmpv6_packet_rx.icmpv6_type == ps_icmpv6.ICMPV6_ECHOREQUEST and icmpv6_packet_rx.icmpv6_code == 0:
        self.logger.debug(f"Received ICMPv6 echo packet from {ipv6_packet_rx.ipv6_src}, sending reply")

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
