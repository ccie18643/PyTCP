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
import asyncio
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


ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = False
ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP = True


async def packet_handler(rx_ring, tx_ring, arp_cache):
    """ Handle basic network protocols like ARP or ICMP """

    logger = loguru.logger.bind(object_name="")

    while True:

        ether_packet_rx = await rx_ring.dequeue()
        logger.debug(f"{ether_packet_rx.serial_number} - {ether_packet_rx.log}")

        # Handle ARP protocol
        if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_ARP:
            arp_packet_rx = ph_arp.ArpPacketRx(ether_packet_rx.raw_data)

            # Handle ARP request
            if arp_packet_rx.hdr_operation == ph_arp.ARP_OP_REQUEST:
                logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number}</green> - {arp_packet_rx.log}")

                # Check if the request is for our IP address, if so the craft ARP reply packet and send it out
                if arp_packet_rx.hdr_tpa == STACK_IP_ADDRESS:

                    arp_packet_tx = ph_arp.ArpPacketTx(
                        hdr_operation=ph_arp.ARP_OP_REPLY,
                        hdr_sha=STACK_MAC_ADDRESS,
                        hdr_spa=STACK_IP_ADDRESS,
                        hdr_tha=arp_packet_rx.hdr_sha,
                        hdr_tpa=arp_packet_rx.hdr_spa,
                    )

                    ether_packet_tx = ph_ether.EtherPacketTx(
                        hdr_src=STACK_MAC_ADDRESS, hdr_dst=arp_packet_tx.hdr_tha, hdr_type=ph_ether.ETHER_TYPE_ARP, raw_data=arp_packet_tx.raw_packet
                    )

                    logger.debug(f"{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number}) - {ether_packet_tx.log}")
                    logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number})</magenta> - {arp_packet_tx.log}")
                    tx_ring.enqueue(ether_packet_tx)

                    # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
                    if ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
                        logger.debug(f"Adding/refreshing ARP cache entry from direct request - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                        arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

            # Handle ARP reply
            if arp_packet_rx.hdr_operation == ph_arp.ARP_OP_REPLY:
                logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number}</green> - {arp_packet_rx.log}")

                # Update ARP cache with maping from received direct ARP reply 
                if ether_packet_rx.hdr_dst == STACK_MAC_ADDRESS: 
                    logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                    arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)
                
                if ether_packet_rx.hdr_dst == "ff:ff:ff:ff:ff:ff" and ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP: 
                    logger.debug(f"Adding/refreshing ARP cache entry from gratitious reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                    arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)


        # Handle IP protocol
        elif ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_IP:
            ip_packet_rx = ph_ip.IpPacketRx(ether_packet_rx.raw_data)
            logger.debug(f"{ether_packet_rx.serial_number} - {ip_packet_rx.log}")

            # Handle IP protocol
            if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_ICMP:
                icmp_packet_rx = ph_icmp.IcmpPacketRx(ip_packet_rx.raw_data)
                logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number}</green> - {icmp_packet_rx.log}")

                # Respond to Echo Request pascket
                if icmp_packet_rx.hdr_type == ph_icmp.ICMP_ECHOREQUEST and icmp_packet_rx.hdr_code == 0:

                    icmp_packet_tx = ph_icmp.IcmpPacketTx(
                        hdr_type=ph_icmp.ICMP_ECHOREPLY,
                        msg_id=icmp_packet_rx.msg_id,
                        msg_seq=icmp_packet_rx.msg_seq,
                        msg_data=icmp_packet_rx.msg_data,
                    )

                    ip_packet_tx = ph_ip.IpPacketTx(
                        hdr_src=STACK_IP_ADDRESS,
                        hdr_dst=ip_packet_rx.hdr_src,
                        hdr_proto=ip_packet_rx.hdr_proto,
                        raw_data=icmp_packet_tx.raw_packet,
                    )

                    ether_packet_tx = ph_ether.EtherPacketTx(
                        hdr_src=STACK_MAC_ADDRESS, hdr_dst="00:00:00:00:00:00", hdr_type=ph_ether.ETHER_TYPE_IP, raw_data=ip_packet_tx.raw_packet
                    )

                    logger.debug(f"{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number}) - {ether_packet_tx.log}")
                    logger.debug(f"{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number}) - {ip_packet_tx.log}")
                    logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number} ({ether_packet_rx.serial_number})</magenta> - {icmp_packet_tx.log}")
                    tx_ring.enqueue(ether_packet_tx)


async def main():
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

    # Initialize ARP cache
    from arp_cache import ArpCache
    arp_cache = ArpCache()

    # Run RX ring operation as separate thread due to its blocking nature
    from rx_ring import RxRing
    rx_ring = RxRing(tap=tap, stack_mac_address=STACK_MAC_ADDRESS)
    thread_rx_ring = threading.Thread(target=rx_ring.handler)
    thread_rx_ring.start()

    # Run TX ring operation as separate thread due to its blocking nature
    from tx_ring import TxRing
    tx_ring = TxRing(tap=tap, stack_mac_address=STACK_MAC_ADDRESS, stack_ip_address=STACK_IP_ADDRESS, arp_cache=arp_cache)
    thread_tx_ring = threading.Thread(target=tx_ring.handler)
    thread_tx_ring.start()

    # Run ARP cache handler as Asyncio coroutine
    task_arp_cache_handler = asyncio.create_task(arp_cache.handler())

    # Run packet handler as Asyncio coroutine
    task_packet_handler = asyncio.create_task(packet_handler(rx_ring, tx_ring, arp_cache=arp_cache))

    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
