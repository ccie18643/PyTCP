#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_icmp.py - packet handler for inbound ICMP packets

"""

import ps_icmp


def phrx_icmp(self, ip_packet_rx, icmp_packet_rx):
    """ Handle inbound ICMP packets """

    self.logger.opt(ansi=True).info(f"<green>{icmp_packet_rx.tracker}</green> - {icmp_packet_rx}")

    # Validate ICMP packet checksum
    if not icmp_packet_rx.validate_cksum():
        self.logger.debug(f"{icmp_packet_rx.tracker} - ICMP packet has invalid checksum, droping")
        return

    # Respond to ICMP Echo Request packet
    if icmp_packet_rx.icmp_type == ps_icmp.ICMP_ECHOREQUEST and icmp_packet_rx.icmp_code == 0:
        self.logger.debug(f"Received ICMP echo packet from {ip_packet_rx.ip_src}, sending reply")

        self.phtx_icmp(
            ip_src=ip_packet_rx.ip_dst,
            ip_dst=ip_packet_rx.ip_src,
            icmp_type=ps_icmp.ICMP_ECHOREPLY,
            icmp_id=icmp_packet_rx.icmp_id,
            icmp_seq=icmp_packet_rx.icmp_seq,
            icmp_raw_data=icmp_packet_rx.icmp_raw_data,
            echo_tracker=icmp_packet_rx.tracker,
        )
        return
