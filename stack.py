#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stact.py - main TCP/IP stack program

"""

import os
import sys
import fcntl
import struct
import loguru
import time
import threading

import ph_ether
import ph_arp
import ph_ip


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

STACK_IF = b"tap7"
STACK_IP_ADDRESS = "192.168.9.7"
STACK_MAC_ADDRESS = "02:00:00:77:77:77"


class RxRing:
    """ Support for receiving packets from the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the inbound queue """

        self.tap = tap
        self.rx_ring = []
        self.serial_number = 0
        self.logger = loguru.logger.bind(object_name="rx_ring.")

    def enqueue(self, packet):
        """ Enqueue inbound pakcet to RX ring """

        packet.serial_number = f"RX{self.serial_number:0>4x}".upper()
        self.serial_number += 1
        if self.serial_number > 0xFFFF:
            self.serial_number = 0

        self.rx_ring.append(packet)

    def dequeue(self):
        """ Dequeue inboutd packet from RX ring """

        while True:
            if not self.rx_ring:
                continue

            return self.rx_ring.pop(0)

    def thread(self):
        """ Thread responsible for receiving and enqueuing incoming packets """

        while True:

            # Read packet from the wire
            packet = ph_ether.EtherPacketIn(os.read(self.tap, 2048))

            # Check if received packet uses valid Ethernet II format
            if packet.hdr_type < ph_ether.ETHER_TYPE_MIN:
                self.logger.opt(ansi=True).debug("<green>[RX]</green> Packet doesn't comply with the Ethernet II standard")
                continue

            # Check if received packet has been sent to us directly or by broadcast
            if packet.hdr_dst not in {STACK_MAC_ADDRESS, "ff:ff:ff:ff:ff:ff"}:
                self.logger.opt(ansi=True).debug("<green>[RX]</green> Packet not destined for this stack")
                continue

            self.enqueue(packet)
            self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {packet.serial_number}")


class TxRing:
    """ Support for sending packets to the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the outbound queue """

        self.tap = tap
        self.tx_ring = []
        self.serial_number = 0
        self.logger = loguru.logger.bind(object_name="tx_ring.")

    def enqueue(self, packet):
        """ Enqueue outbound Ethernet packet to TX ring """

        packet.serial_number = f"TX{self.serial_number:0>4x}".upper()
        self.serial_number += 1
        if self.serial_number > 0xFFFF:
            self.serial_number = 0

        self.tx_ring.append(packet)

    def dequeue(self):
        """ Dequeue packet from TX ring """

        while True:

            if not self.tx_ring:
                continue

            return self.tx_ring.pop(0)

    def thread(self):
        """ Thread responsible for dequeuing and sending outgoing packets """

        while True:
            packet = self.dequeue()
            os.write(self.tap, packet.raw_packet)
            self.logger.opt(ansi=True).debug(f"<magenta>[TX]</magenta> {packet.serial_number}")


def packet_handler(rx_ring, tx_ring):
    """ Handle basic network protocols like ARP or ICMP """

    logger = loguru.logger.bind(object_name="")

    while True:

        ether_packet_in = rx_ring.dequeue()
        logger.debug(f"{ether_packet_in.serial_number} - {ether_packet_in.log}")

        # Handle ARP request
        if ether_packet_in.hdr_type == ph_ether.ETHER_TYPE_ARP:
            arp_packet_in = ph_arp.ArpPacketIn(ether_packet_in.raw_data)

            if arp_packet_in.hdr_operation == ph_arp.ARP_OP_REQUEST:
                logger.opt(ansi=True).info(f"<green>{ether_packet_in.serial_number}</green> - {arp_packet_in.log}")

                # Check if the request is for our MAC address, if so the craft ARP reply packet and send it out
                if arp_packet_in.hdr_tpa == STACK_IP_ADDRESS:

                    arp_packet_out = ph_arp.ArpPacketOut(
                        hdr_operation=ph_arp.ARP_OP_REPLY,
                        hdr_sha=STACK_MAC_ADDRESS,
                        hdr_spa=STACK_IP_ADDRESS,
                        hdr_tha=arp_packet_in.hdr_sha,
                        hdr_tpa=arp_packet_in.hdr_spa,
                    )

                    ether_packet_out = ph_ether.EtherPacketOut(
                        hdr_src=STACK_MAC_ADDRESS, hdr_dst=arp_packet_out.hdr_tha, hdr_type=ph_ether.ETHER_TYPE_ARP, raw_data=arp_packet_out.raw_packet
                    )

                    tx_ring.enqueue(ether_packet_out)
                    logger.debug(f"{ether_packet_out.serial_number} - {ether_packet_out.log}")
                    logger.opt(ansi=True).info(f"<magenta>{ether_packet_out.serial_number}</magenta> - {arp_packet_out.log}")

        elif ether_packet_in.hdr_type == ph_ether.ETHER_TYPE_IP:
            ip_packet_in = ph_ip.IpPacketIn(ether_packet_in.raw_data)
            logger.debug(f"{ether_packet_in.serial_number} - {ip_packet_in.log}")

            if ip_packet_in.hdr_proto == ph_ip.IP_PROTO_ICMP:


                ip_packet_out = ph_ip.IpPacketOut(
                    hdr_src=STACK_IP_ADDRESS,
                    hdr_dst=ip_packet_in.hdr_src,
                    hdr_proto=ip_packet_in.hdr_proto,
                    raw_options=ip_packet_in.raw_options,
                )

                ether_packet_out = ph_ether.EtherPacketOut(
                    hdr_src=STACK_MAC_ADDRESS, hdr_dst=ether_packet_in.hdr_src, hdr_type=ph_ether.ETHER_TYPE_IP, raw_data=ip_packet_out.raw_packet
                )

                tx_ring.enqueue(ether_packet_out)
                logger.debug(f"{ether_packet_out.serial_number} - {ether_packet_out.log}")
                logger.opt(ansi=True).info(f"<magenta>{ether_packet_out.serial_number}</magenta> - {ip_packet_out.log}")


def main():
    """ Main function """

    loguru.logger.remove(0)
    loguru.logger.add(
        sys.stdout,
        colorize=True,
        level="DEBUG",
        format="<green>{time:YY-MM-DD HH:mm:ss}</green> <level>| {level:7} "
        + "|</level> <level> <normal><cyan>{extra[object_name]}{function}:</cyan></normal> {message}</level>",
    )

    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", STACK_IF, IFF_TAP | IFF_NO_PI))

    rx_ring = RxRing(tap)
    tx_ring = TxRing(tap)

    thread_rx_ring = threading.Thread(target=rx_ring.thread)
    thread_rx_ring.start()

    thread_tx_ring = threading.Thread(target=tx_ring.thread)
    thread_tx_ring.start()

    thread_packet_handler = threading.Thread(target=packet_handler, args=(rx_ring, tx_ring))
    thread_packet_handler.start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
