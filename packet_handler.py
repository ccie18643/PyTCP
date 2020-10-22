#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack.py - main TCP/IP stack program

"""

import os
import sys
import fcntl
import struct
import loguru

import ph_ether
import ph_arp
import ph_ip
import ph_icmp
import ph_udp
import ph_tcp

from arp_cache import ArpCache
from rx_ring import RxRing
from tx_ring import TxRing
from socket_support import Sockets

from service_udp_echo import ServiceUdpEcho


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

STACK_IF = b"tap7"
STACK_IP_ADDRESS = "192.168.9.7"
STACK_MAC_ADDRESS = "02:00:00:77:77:77"

ARP_CACHE_BYPASS_ON_RESPONSE = False
ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = False
ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP = True

UDP_PORT_ECHO = 7

STACK_UDP_ECHO_ENABLED = True


class PacketHandler:
    """ Pick up incomming packets and react to them aproprietly """


def arp_packet_handler(ether_packet_rx, arp_packet_rx, arp_cache, tx_ring, logger):
    """ Handle incomming ARP packets """

    # Handle ARP request
    if arp_packet_rx.hdr_oper == ph_arp.ARP_OP_REQUEST:
        logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {arp_packet_rx}")

        # Check if the request is for our IP address, if so the craft ARP reply packet and send it out
        if arp_packet_rx.hdr_tpa == STACK_IP_ADDRESS:

            arp_packet_tx = ph_arp.ArpPacket(
                hdr_oper=ph_arp.ARP_OP_REPLY,
                hdr_sha=STACK_MAC_ADDRESS,
                hdr_spa=STACK_IP_ADDRESS,
                hdr_tha=arp_packet_rx.hdr_sha,
                hdr_tpa=arp_packet_rx.hdr_spa,
            )

            ether_packet_tx = ph_ether.EtherPacket(hdr_src=STACK_MAC_ADDRESS, hdr_dst=arp_packet_tx.hdr_tha, child_packet=arp_packet_tx)

            # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
            ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
            ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

            logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
            logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {arp_packet_tx}")
            tx_ring.enqueue(ether_packet_tx)

            # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
            if ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
                logger.debug(f"Adding/refreshing ARP cache entry from direct request - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

    # Handle ARP reply
    elif arp_packet_rx.hdr_oper == ph_arp.ARP_OP_REPLY:
        logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {arp_packet_rx}")

        # Update ARP cache with maping received as direct ARP reply
        if ether_packet_rx.hdr_dst == STACK_MAC_ADDRESS:
            logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

        # Update ARP cache with maping received as gratitious ARP reply
        if ether_packet_rx.hdr_dst == "ff:ff:ff:ff:ff:ff" and ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP:
            logger.debug(f"Adding/refreshing ARP cache entry from gratitious reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)


def icmp_packet_handler(ether_packet_rx, ip_packet_rx, icmp_packet_rx, tx_ring, logger):
    """ Handle incoming ICMP packets """

    logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {icmp_packet_rx}")

    # Respond to ICMP Echo Request packet
    if icmp_packet_rx.hdr_type == ph_icmp.ICMP_ECHOREQUEST and icmp_packet_rx.hdr_code == 0:
        logger.debug(f"Received ICMP echo packet from {ip_packet_rx.hdr_src}, sending reply")

        icmp_packet_tx = ph_icmp.IcmpPacket(
            hdr_type=ph_icmp.ICMP_ECHOREPLY, msg_id=icmp_packet_rx.msg_id, msg_seq=icmp_packet_rx.msg_seq, msg_data=icmp_packet_rx.msg_data
        )

        ip_packet_tx = ph_ip.IpPacket(hdr_src=STACK_IP_ADDRESS, hdr_dst=ip_packet_rx.hdr_src, child_packet=icmp_packet_tx)

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
        logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {icmp_packet_tx}")
        tx_ring.enqueue(ether_packet_tx)


def udp_packet_handler(ether_packet_rx, ip_packet_rx, udp_packet_rx, sockets, tx_ring, logger):
    """ Handle incoming UDP packets """

    logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {udp_packet_rx}")

    # Socket mechanism support
    socket = sockets.match_listening(
        protocol="UDP",
        local_ip_address=ip_packet_rx.hdr_dst,
        local_port=udp_packet_rx.hdr_dport,
        serial_number_rx=ether_packet_rx.serial_number_rx,
    )

    if socket:
        print("LISTENING SOCKET MATCH:", socket)

    # Respond with ICMP Port Unreachable message
    else:
        logger.debug(f"Received UDP packet from {ip_packet_rx.hdr_src} to closed port {udp_packet_rx.hdr_dport}, sending ICMP Port Unreachable")

        icmp_packet_tx = ph_icmp.IcmpPacket(hdr_type=ph_icmp.ICMP_UNREACHABLE, hdr_code=ph_icmp.ICMP_UNREACHABLE_PORT, ip_packet_rx=ip_packet_rx)

        ip_packet_tx = ph_ip.IpPacket(hdr_src=STACK_IP_ADDRESS, hdr_dst=ip_packet_rx.hdr_src, child_packet=icmp_packet_tx)

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
        logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {icmp_packet_tx}")
        tx_ring.enqueue(ether_packet_tx)


def tcp_packet_handler(ether_packet_rx, ip_packet_rx, tcp_packet_rx, sockets, tx_ring, logger):
    """ Handle incoming TCP packets """

    logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {tcp_packet_rx}")

    # Socket mechanism support
    if False:
        pass

    else:
        logger.debug(f"Received TCP packet from {ip_packet_rx.hdr_src} to closed port {tcp_packet_rx.hdr_dport}, sending TCP Reset packet")

        tcp_packet_tx = ph_tcp.TcpPacket(
            hdr_sport=tcp_packet_rx.hdr_dport,
            hdr_dport=tcp_packet_rx.hdr_sport,
            hdr_ack_num=tcp_packet_rx.hdr_seq_num + 1,
            hdr_flag_rst=True,
            hdr_flag_ack=True,
        )

        ip_packet_tx = ph_ip.IpPacket(hdr_src=STACK_IP_ADDRESS, hdr_dst=ip_packet_rx.hdr_src, child_packet=tcp_packet_tx)

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
        logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {tcp_packet_tx}")
        tx_ring.enqueue(ether_packet_tx)


def ip_packet_handler(ether_packet_rx, ip_packet_rx, sockets, tx_ring, logger):
    """ Handle incoming IP packets """

    logger.debug(f"{ether_packet_rx.serial_number_rx} - {ip_packet_rx}")

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_ICMP:
        icmp_packet_handler(ether_packet_rx, ip_packet_rx, ph_icmp.IcmpPacket(ip_packet_rx), tx_ring, logger)

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_UDP:
        udp_packet_handler(ether_packet_rx, ip_packet_rx, ph_udp.UdpPacket(ip_packet_rx), sockets, tx_ring, logger)

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_TCP:
        tcp_packet_handler(ether_packet_rx, ip_packet_rx, ph_tcp.TcpPacket(ip_packet_rx), sockets, tx_ring, logger)


def ether_packet_handler(ether_packet_rx, tx_ring, arp_cache, sockets, logger):
    """ Handle incoming Ethernet packets """

    logger.debug(f"{ether_packet_rx.serial_number_rx} - {ether_packet_rx}")

    if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_ARP:
        arp_packet_handler(ether_packet_rx, ph_arp.ArpPacket(ether_packet_rx), arp_cache, tx_ring, logger)

    if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_IP:
        ip_packet_handler(ether_packet_rx, ph_ip.IpPacket(ether_packet_rx), sockets, tx_ring, logger)


def packet_handler(rx_ring, tx_ring, arp_cache, sockets, logger):
    """ Pickup incoming packets from RX ring and process them """

    while True:
        ether_packet_handler(rx_ring.dequeue(), tx_ring, arp_cache, sockets, logger)


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

    logger = loguru.logger.bind(object_name="")

    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", STACK_IF, IFF_TAP | IFF_NO_PI))

    arp_cache = ArpCache(stack_mac_address=STACK_MAC_ADDRESS, stack_ip_address=STACK_IP_ADDRESS)
    rx_ring = RxRing(tap=tap, stack_mac_address=STACK_MAC_ADDRESS)
    tx_ring = TxRing(tap=tap, stack_mac_address=STACK_MAC_ADDRESS, stack_ip_address=STACK_IP_ADDRESS, arp_cache=arp_cache)
    sockets = Sockets(stack_mac_address=STACK_MAC_ADDRESS, stack_ip_address=STACK_IP_ADDRESS)
    ServiceUdpEcho(sockets)
    packet_handler(rx_ring, tx_ring, arp_cache, sockets, logger)


if __name__ == "__main__":
    sys.exit(main())
