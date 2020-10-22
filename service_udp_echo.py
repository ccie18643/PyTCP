#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
service_udp_echo.py - 'user space' service UDP echo

"""

import time
import threading


class ServiceUdpEcho:
    """ UDP Echo service support class """

    def __init__(self, socket):
        """ Class constructor """

        self.socket = socket

        threading.Thread(target=self.__service).start()

    def __service(self):

        self.socket.open("UDP", 7)

        while True:
            time.sleep(1)


"""
                # Support for UDP Echo protocol <-- will be moved to "user space" once socket support is completed
                if STACK_UDP_ECHO_ENABLED and udp_packet_rx.hdr_dport == UDP_PORT_ECHO:
                    logger.debug(f"Received UDP echo packet from {ip_packet_rx.hdr_src}, sending reply")

                    udp_packet_tx = ph_udp.UdpPacket(hdr_sport=udp_packet_rx.hdr_dport, hdr_dport=udp_packet_rx.hdr_sport, raw_data=udp_packet_rx.raw_data)

                    ip_packet_tx = ph_ip.IpPacket(hdr_src=STACK_IP_ADDRESS, hdr_dst=ip_packet_rx.hdr_src, child_packet=udp_packet_tx)

                    ether_packet_tx = ph_ether.EtherPacket(
                        hdr_src=STACK_MAC_ADDRESS,
                        hdr_dst=ether_packet_rx.hdr_src if ARP_CACHE_BYPASS_ON_RESPONSE else "00:00:00:00:00:00",
                        child_packet=ip_packet_tx,
                    )

                    # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
                    ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
                    ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

                    logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
                    logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ip_packet_tx}")
                    logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {udp_packet_tx}")
                    tx_ring.enqueue(ether_packet_tx)
"""
