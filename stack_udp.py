#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack_udp.py - part of TCP/IP stack responsible of handling UDP packets

"""

from udp_socket import UdpSocket

import ph_ether
import ph_ip
import ph_icmp


def udp_packet_handler(self, ether_packet_rx, ip_packet_rx, udp_packet_rx):
    """ Handle incoming UDP packets """

    self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {udp_packet_rx}")

    # Check if incoming packet matches any listening socket
    socket = UdpSocket.match_listening(
        local_ip_address=ip_packet_rx.hdr_dst,
        local_port=udp_packet_rx.hdr_dport,
        serial_number_rx=ether_packet_rx.serial_number_rx,
    )
    if socket:
        socket.enqueue(
            src_ip_address=ip_packet_rx.hdr_src,
            src_port=udp_packet_rx.hdr_sport,
            raw_data=udp_packet_rx.raw_data,
            serial_number_rx=ether_packet_rx.serial_number_rx,
            timestamp_rx=ether_packet_rx.timestamp_rx,
        )
        return

    # In case incoming packet did't mach any listening port respond with ICMP Port Unreachable message
    self.logger.debug(f"Received UDP packet from {ip_packet_rx.hdr_src} to closed port {udp_packet_rx.hdr_dport}, sending ICMP Port Unreachable")

    icmp_packet_tx = ph_icmp.IcmpPacket(hdr_type=ph_icmp.ICMP_UNREACHABLE, hdr_code=ph_icmp.ICMP_UNREACHABLE_PORT, ip_packet_rx=ip_packet_rx)
    ip_packet_tx = ph_ip.IpPacket(hdr_src=self.stack_ip_address, hdr_dst=ip_packet_rx.hdr_src, child_packet=icmp_packet_tx)
    ether_packet_tx = ph_ether.EtherPacket(child_packet=ip_packet_tx)

    # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
    ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
    ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

    self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
    self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ip_packet_tx}")
    self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {icmp_packet_tx}")
    self.tx_ring.enqueue(ether_packet_tx)
