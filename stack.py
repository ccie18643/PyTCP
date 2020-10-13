#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stact.py - main TCP/IP stack program

"""

import os
import sys
import fcntl
import struct
import asyncio
import loguru

import ph_ethernet
import ph_arp


STACK_IP_ADDRESS = "10.0.0.7"
STACK_MAC_ADDRESS = "aa:bb:cc:dd:ee:ff"

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


async def packet_handler():
    """ Loop receiving packets and handling basic network protocols like ARP or ICMP """

    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", b"tap0", IFF_TAP | IFF_NO_PI))

    while True:

        # Read packet from the wire
        packet_in = os.read(tap, 1500)

        # Check if received packet uses valid Ethernet II format
        if struct.unpack("!H", packet_in[12:14])[0] < ph_ethernet.ETHERTYPE_MIN:
            loguru.logger.warning("Recived packet that doesn't comply with the Ethernet II standard")
            continue

        ethernet_packet_in = ph_ethernet.EthernetPacket(packet_in)

        # Check if received packet has been sent to us directly or by broadcast
        if ethernet_packet_in.dst not in {STACK_MAC_ADDRESS, "ff:ff:ff:ff:ff:ff"}:
            loguru.logger.debug("Recived Ethernet packet that is not destined for this stack")
            continue

        # Handle ARP request
        if ethernet_packet_in.ethertype == ph_ethernet.ETHERTYPE_ARP:
            arp_packet_in = ph_arp.ArpPacket(ethernet_packet_in.raw_data)

            if arp_packet_in.operation == ph_arp.ARP_OP_REQUEST:
                loguru.logger.debug(f"Received ARP request for {arp_packet_in.tpa} from {arp_packet_in.spa} ({arp_packet_in.sha})")

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

                    # Put the eply packet on the wire
                    os.write(tap, ethernet_packet_out.raw_packet)

                    loguru.logger.debug(f"Sent ARP reply for {arp_packet_out.spa} ({arp_packet_out.sha}) to {arp_packet_out.tpa} ({arp_packet_out.tha})")


async def main():
    """ Main function """

    loguru.logger.remove(0)
    loguru.logger.add(
        sys.stdout,
        colorize=True,
        level="DEBUG",
        format=f"<green>{{time:YY-MM-DD HH:mm:ss}}</green> <level>| {{level:7}} "
        + f"|</level> <level> <normal><cyan>{{function:20}}</cyan></normal> | {{message}}</level>",
    )

    await packet_handler()


if __name__ == "__main__":
    asyncio.run(main())
