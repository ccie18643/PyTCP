#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ps_tcp_rx.py - part of TCP/IP stack responsible of handling TCP packets

"""


import ps_ether
import ps_ip
import ps_tcp


def tcp_packet_handler(self, ether_packet_rx, ip_packet_rx, tcp_packet_rx):
    """ Handle incoming TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {tcp_packet_rx}")

    # Socket mechanism support
    if False:
        pass

    else:
        self.logger.debug(f"Received TCP packet from {ip_packet_rx.hdr_src} to closed port {tcp_packet_rx.hdr_dport}, sending TCP Reset packet")

        tcp_packet_tx = ps_tcp.TcpPacket(
            hdr_sport=tcp_packet_rx.hdr_dport,
            hdr_dport=tcp_packet_rx.hdr_sport,
            hdr_ack_num=tcp_packet_rx.hdr_seq_num + 1,
            hdr_flag_rst=True,
            hdr_flag_ack=True,
        )
        ip_packet_tx = ps_ip.IpPacket(hdr_src=self.ps_ip_rx_address, hdr_dst=ip_packet_rx.hdr_src, child_packet=tcp_packet_tx)
        ether_packet_tx = ps_ether.EtherPacket(child_packet=ip_packet_tx)

        # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
        ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
        ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

        self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
        self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ip_packet_tx}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {tcp_packet_tx}")
        self.tx_ring.enqueue(ether_packet_tx)
