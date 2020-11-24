#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
sniffer.py - tool used to test protocol handler classes

"""

import sys
import socket

import ps_ether
import ps_arp
import ps_ipv4
import ps_ipv6
import ps_icmpv4
import ps_udp
import ps_tcp


# raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
# raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3))


def main():
    while True:
        raw_packet_rx = raw_socket.recv(2048)
        ether_packet_rx = ps_ether.EtherPacket(raw_packet_rx)

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_ARP:
            arp_packet_rx = ps_arp.ArpPacket(ether_packet_rx)
            print("-" * 160)
            print(ether_packet_rx)
            print(arp_packet_rx)
            print("-" * 160)
            continue

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IPV6:
            ipv6_packet_rx = ps_ipv6.IPv6Packet(ether_packet_rx)
            print("-" * 160)
            print(ether_packet_rx)
            print(ipv6_packet_rx)
            continue

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP:
            ipv4_packet_rx = ps_ipv4.IPv4Packet(ether_packet_rx)

            if ipv4_packet_rx.ipv4_proto == ps_ipv4.IPV4_PROTO_ICMPv4:
                icmpv4_packet_rx = ps_icmpv4.ICMPv4Packet(ipv4_packet_rx)
                print("-" * 160)
                print(ether_packet_rx)
                print(ipv4_packet_rx)
                print(icmpv4_packet_rx)
                print("-" * 160)
                continue

            if ipv4_packet_rx.ipv4_proto == ps_ipv4.IPV4_PROTO_UDP:
                udp_packet_rx = ps_udp.UdpPacket(ipv4_packet_rx)
                print("-" * 160)
                print(ether_packet_rx)
                print(ipv4_packet_rx)
                print(udp_packet_rx)
                print("-" * 160)
                continue

            if ipv4_packet_rx.ipv4_proto == ps_ipv4.IPV4_PROTO_TCP:
                tcp_packet_rx = ps_tcp.TcpPacket(ipv4_packet_rx)
                if 22 in {tcp_packet_rx.tcp_dport, tcp_packet_rx.tcp_sport}:
                    continue
                print("-" * 160)
                print(ether_packet_rx)
                print(ipv4_packet_rx)
                print(tcp_packet_rx)
                print("-" * 160)
                continue

        print("-" * 160)
        print(ether_packet_rx)


if __name__ == "__main__":
    sys.exit(main())
