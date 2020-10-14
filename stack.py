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

import ph_ethernet
import ph_arp

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

        packet.serial_number = f"RX-{self.serial_number:0>4x}"
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
            packet = ph_ethernet.EthernetPacket(os.read(self.tap, 2048))

            # Check if received packet uses valid Ethernet II format
            if packet.ethertype < ph_ethernet.ETHERTYPE_MIN:
                self.logger.warning("Recived packet that doesn't comply with the Ethernet II standard")
                continue

            # Check if received packet has been sent to us directly or by broadcast
            if packet.dst not in {STACK_MAC_ADDRESS, "ff:ff:ff:ff:ff:ff"}:
                self.logger.debug("Recived Ethernet packet that is not destined for this stack")
                continue

            self.enqueue(packet)
            self.logger.opt(ansi=True).debug(f"<red>[RX]</red> Received inbound packet ({packet.serial_number})")


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

        packet.serial_number = f"TX-{self.serial_number:0>4x}"
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
            self.logger.opt(ansi=True).debug(f"<green>[TX]</green> Sent out Ethernet packet ({packet.serial_number})")


def packet_handler(rx_ring, tx_ring):
    """ Handle basic network protocols like ARP or ICMP """

    logger = loguru.logger.bind(object_name="")

    while True:

        ethernet_packet_in = rx_ring.dequeue()

        # Handle ARP request
        if ethernet_packet_in.ethertype == ph_ethernet.ETHERTYPE_ARP:
            arp_packet_in = ph_arp.ArpPacket(ethernet_packet_in.raw_data)

            if arp_packet_in.operation == ph_arp.ARP_OP_REQUEST:
                logger.info(f"Dequeued ARP {arp_packet_in}")

                # Check if the request is for our MAC address, if so the craft ARP reply packet and send it out
                if arp_packet_in.tpa == STACK_IP_ADDRESS:

                    arp_packet_out = ph_arp.ArpPacket(
                        operation=ph_arp.ARP_OP_REPLY,
                        sha=STACK_MAC_ADDRESS,
                        spa=STACK_IP_ADDRESS,
                        tha=arp_packet_in.sha,
                        tpa=arp_packet_in.spa,
                    )

                    ethernet_packet_out = ph_ethernet.EthernetPacket(
                        src=STACK_MAC_ADDRESS, dst=arp_packet_out.tha, ethertype=ph_ethernet.ETHERTYPE_ARP, raw_data=arp_packet_out.raw_packet
                    )

                    tx_ring.enqueue(ethernet_packet_out)
                    logger.info(f"Enqueued ARP {arp_packet_out}")

        else:
            logger.debug(f"Dequeued not supported packet ({ethernet_packet_in.serial_number}) {ethernet_packet_in}")


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
