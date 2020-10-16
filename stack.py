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
import ph_icmp


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

STACK_IF = b"tap7"
STACK_IP_ADDRESS = "192.168.9.7"
STACK_MAC_ADDRESS = "02:00:00:77:77:77"


ARP_CACHE = {}
ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = False

TX_RING_RETRY_COUNT = 3
TX_RING_RETRY_DELAY = 0.1


class RxRing:
    """ Support for receiving packets from the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the inbound queue """

        self.tap = tap
        self.rx_ring = []
        self.logger = loguru.logger.bind(object_name="rx_ring.")

    def enqueue(self, ether_packet_rx):
        """ Enqueue inbound pakcet to RX ring """

        self.rx_ring.append(ether_packet_rx)

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
            ether_packet_rx = ph_ether.EtherPacketIn(os.read(self.tap, 2048))

            # Check if received packet uses valid Ethernet II format
            if ether_packet_rx.hdr_type < ph_ether.ETHER_TYPE_MIN:
                self.logger.opt(ansi=True).debug("<green>[RX]</green> Packet doesn't comply with the Ethernet II standard")
                continue

            # Check if received packet has been sent to us directly or by broadcast
            if ether_packet_rx.hdr_dst not in {STACK_MAC_ADDRESS, "ff:ff:ff:ff:ff:ff"}:
                self.logger.opt(ansi=True).debug("<green>[RX]</green> Packet not destined for this stack")
                continue

            self.enqueue(ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.serial_number}")


class TxRing:
    """ Support for sending packets to the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the outbound queue """

        self.tap = tap
        self.tx_ring = []
        self.logger = loguru.logger.bind(object_name="tx_ring.")

    def enqueue_arp_request(self, hdr_tpa):
        """ Enqueue ARP request """

        arp_packet_tx = ph_arp.ArpPacketOut(
            hdr_operation=ph_arp.ARP_OP_REQUEST,
            hdr_sha=STACK_MAC_ADDRESS,
            hdr_spa=STACK_IP_ADDRESS,
            hdr_tha="00:00:00:00:00:00",
            hdr_tpa=hdr_tpa,
        )

        ether_packet_tx = ph_ether.EtherPacketOut(
            hdr_src=STACK_MAC_ADDRESS, hdr_dst="ff:ff:ff:ff:ff:ff", hdr_type=ph_ether.ETHER_TYPE_ARP, raw_data=arp_packet_tx.raw_packet
        )

        self.logger.debug(f"{ether_packet_tx.serial_number} - {ether_packet_tx.log}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number} </magenta> - {arp_packet_tx.log}")
        self.enqueue(ether_packet_tx, urgent=True)

    def enqueue(self, ether_packet_tx, urgent=False):
        """ Enqueue outbound Ethernet packet to TX ring """

        if urgent:
            self.tx_ring.insert(0, ether_packet_tx)

        else:
            self.tx_ring.append(ether_packet_tx)

    def dequeue(self):
        """ Dequeue packet from TX ring """

        while True:

            if not self.tx_ring:
                continue

            ether_packet_tx = self.tx_ring.pop(0)

            # Check if packet should be delayed
            if ether_packet_tx.retry_timestamp and ether_packet_tx.retry_timestamp < time.time():
                self.enqueue(ether_packet_tx)
                continue

            # In case Ethernet packet contains valid destination MAC send it out
            if ether_packet_tx.hdr_dst != "00:00:00:00:00:00":
                self.logger.debug(f"{ether_packet_tx.serial_number} Contains valid destination MAC address")
                return ether_packet_tx

            # If above is not true then check if Ethernet packet carries IP packet
            if ether_packet_tx.hdr_type == ph_ether.ETHER_TYPE_IP:
                ip_packet_tx = ph_ip.IpPacketIn(ether_packet_tx.raw_data)

                # Try to resolve destination IP -> MAC using ARP cache
                if arp_cache_entry := ARP_CACHE.get(ip_packet_tx.hdr_dst, None):
                    ether_packet_tx.hdr_dst = arp_cache_entry
                    self.logger.debug(f"{ether_packet_tx.serial_number} Resolved destiantion IP {ip_packet_tx.hdr_dst} to MAC ({ether_packet_tx.hdr_dst})")
                    return ether_packet_tx

                # If we don't have valid ARP cache entry for given destination IP send out ARP request for it and delay the packet if appropriate
                else:
                    self.logger.debug(
                        f"{ether_packet_tx.serial_number} Unable to resolve destiantion IP to MAC, sending ARP request for {ip_packet_tx.hdr_dst}"
                    )

                    self.enqueue_arp_request(ip_packet_tx.hdr_dst)

                    # Incremet retry counter and if its within the limit enqueue original packet with current timestamp
                    ether_packet_tx.retry_counter += 1

                    if ether_packet_tx.retry_counter <= TX_RING_RETRY_COUNT:
                        ether_packet_tx.retry_timestamp = time.time() + TX_RING_RETRY_DELAY
                        self.enqueue(ether_packet_tx)
                        self.logger.debug(
                            f"{ether_packet_tx.serial_number} Delaying packet for {TX_RING_RETRY_DELAY}s, retry counter {ether_packet_tx.retry_counter}"
                        )
                        continue
                        
            self.logger.debug(
                f"{ether_packet_tx.serial_number} Droping packet"
            )

    def thread(self):
        """ Thread responsible for dequeuing and sending outgoing packets """

        while True:
            ether_packet_tx = self.dequeue()
            os.write(self.tap, ether_packet_tx.raw_packet)
            self.logger.opt(ansi=True).debug(f"<magenta>[TX]</magenta> {ether_packet_tx.serial_number} - {ether_packet_tx.log}")


def packet_handler(rx_ring, tx_ring):
    """ Handle basic network protocols like ARP or ICMP """

    logger = loguru.logger.bind(object_name="")

    while True:

        ether_packet_rx = rx_ring.dequeue()
        logger.debug(f"{ether_packet_rx.serial_number} - {ether_packet_rx.log}")

        # Handle ARP protocol
        if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_ARP:
            arp_packet_rx = ph_arp.ArpPacketIn(ether_packet_rx.raw_data)

            # Handle ARP request
            if arp_packet_rx.hdr_operation == ph_arp.ARP_OP_REQUEST:
                logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number}</green> - {arp_packet_rx.log}")

                # Check if the request is for our IP address, if so the craft ARP reply packet and send it out
                if arp_packet_rx.hdr_tpa == STACK_IP_ADDRESS:

                    arp_packet_tx = ph_arp.ArpPacketOut(
                        hdr_operation=ph_arp.ARP_OP_REPLY,
                        hdr_sha=STACK_MAC_ADDRESS,
                        hdr_spa=STACK_IP_ADDRESS,
                        hdr_tha=arp_packet_rx.hdr_sha,
                        hdr_tpa=arp_packet_rx.hdr_spa,
                    )

                    ether_packet_tx = ph_ether.EtherPacketOut(
                        hdr_src=STACK_MAC_ADDRESS, hdr_dst=arp_packet_tx.hdr_tha, hdr_type=ph_ether.ETHER_TYPE_ARP, raw_data=arp_packet_tx.raw_packet
                    )

                    logger.debug(f"{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number}) - {ether_packet_tx.log}")
                    logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number})</magenta> - {arp_packet_tx.log}")
                    tx_ring.enqueue(ether_packet_tx)

                    # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
                    if ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
                        logger.debug(f"Adding/refreshing ARP cache entry {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                        ARP_CACHE[arp_packet_rx.hdr_spa] = arp_packet_rx.hdr_sha

            # Handle ARP reply
            if arp_packet_rx.hdr_operation == ph_arp.ARP_OP_REPLY:
                logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number}</green> - {arp_packet_rx.log}")

                # Update ARP cache with maping from received ARP reply for the request this stack sent earlier
                logger.debug(f"Adding/refreshing ARP cache entry {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                ARP_CACHE[arp_packet_rx.hdr_spa] = arp_packet_rx.hdr_sha

        # Handle IP protocol
        elif ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_IP:
            ip_packet_rx = ph_ip.IpPacketIn(ether_packet_rx.raw_data)
            logger.debug(f"{ether_packet_rx.serial_number} - {ip_packet_rx.log}")

            # Handle IP protocol
            if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_ICMP:
                icmp_packet_rx = ph_icmp.IcmpPacketIn(ip_packet_rx.raw_data)
                logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number}</green> - {icmp_packet_rx.log}")

                # Respond to Echo Request pascket
                if icmp_packet_rx.hdr_type == ph_icmp.ICMP_ECHOREQUEST and icmp_packet_rx.hdr_code == 0:

                    icmp_packet_tx = ph_icmp.IcmpPacketOut(
                        hdr_type=ph_icmp.ICMP_ECHOREPLY,
                        msg_id=icmp_packet_rx.msg_id,
                        msg_seq=icmp_packet_rx.msg_seq,
                        msg_data=icmp_packet_rx.msg_data,
                    )

                    ip_packet_tx = ph_ip.IpPacketOut(
                        hdr_src=STACK_IP_ADDRESS,
                        hdr_dst=ip_packet_rx.hdr_src,
                        hdr_proto=ip_packet_rx.hdr_proto,
                        raw_data=icmp_packet_tx.raw_packet,
                    )

                    ether_packet_tx = ph_ether.EtherPacketOut(
                        hdr_src=STACK_MAC_ADDRESS, hdr_dst="00:00:00:00:00:00", hdr_type=ph_ether.ETHER_TYPE_IP, raw_data=ip_packet_tx.raw_packet
                    )

                    logger.debug(f"{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number}) - {ether_packet_tx.log}")
                    logger.debug(f"{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number}) - {ip_packet_tx.log}")
                    logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number})</magenta> - {icmp_packet_tx.log}")
                    tx_ring.enqueue(ether_packet_tx)


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
