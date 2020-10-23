#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ps_icmp_rx.py - part of TCP/IP stack responsible for handling ICMP packets

"""

import ps_ether
import ps_ip
import ps_icmp


def icmp_packet_handler(self, ether_packet_rx, ip_packet_rx, icmp_packet_rx):
    """ Handle incoming ICMP packets """

    self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {icmp_packet_rx}")

    # Respond to ICMP Echo Request packet
    if icmp_packet_rx.hdr_type == ps_icmp.ICMP_ECHOREQUEST and icmp_packet_rx.hdr_code == 0:
        self.logger.debug(f"Received ICMP echo packet from {ip_packet_rx.hdr_src}, sending reply")

        icmp_packet_tx = ps_icmp.IcmpPacket(
            hdr_type=ps_icmp.ICMP_ECHOREPLY, msg_id=icmp_packet_rx.msg_id, msg_seq=icmp_packet_rx.msg_seq, msg_data=icmp_packet_rx.msg_data
        )
        ip_packet_tx = ps_ip.IpPacket(hdr_src=self.ps_ip_rx_address, hdr_dst=ip_packet_rx.hdr_src, child_packet=icmp_packet_tx)
        ether_packet_tx = ps_ether.EtherPacket(child_packet=ip_packet_tx)

        # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
        ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
        ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

        self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
        self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ip_packet_tx}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {icmp_packet_tx}")
        self.tx_ring.enqueue(ether_packet_tx)
