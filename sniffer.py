#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
sniffer.py - tool used to test protocol handler classes

"""

import sys
import socket

import ps_ether
import ps_arp
import ps_ip
import ps_icmp
import ps_udp
import ps_tcp

# import ps_tcp

raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


def main():
    while True:
        raw_packet_rx = raw_socket.recv(2048)
        ether_packet_rx = ps_ether.EtherPacket(raw_packet_rx)

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_ARP:
            arp_packet_rx = ps_arp.ArpPacket(ether_packet_rx)
            print("-" * 80)
            print(ether_packet_rx)
            print(arp_packet_rx)
            print("-" * 80)

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP:
            ip_packet_rx = ps_ip.IpPacket(ether_packet_rx)

            if ip_packet_rx.ip_proto == ps_ip.IP_PROTO_ICMP:
                icmp_packet_rx = ps_icmp.IcmpPacket(ip_packet_rx)
                print("-" * 80)
                print(ether_packet_rx)
                print(ip_packet_rx)
                print(icmp_packet_rx)
                print("-" * 80)

            if ip_packet_rx.ip_proto == ps_ip.IP_PROTO_UDP:
                udp_packet_rx = ps_udp.UdpPacket(ip_packet_rx)
                print("-" * 80)
                print(ether_packet_rx)
                print(ip_packet_rx)
                print(udp_packet_rx)
                print("-" * 80)

            if ip_packet_rx.ip_proto == ps_ip.IP_PROTO_TCP:
                tcp_packet_rx = ps_tcp.TcpPacket(ip_packet_rx)
                if tcp_packet_rx.tcp_dport == 22:
                    continue
                print("-" * 80)
                print(ether_packet_rx)
                print(ip_packet_rx)
                print(tcp_packet_rx)
                print("-" * 80)


if __name__ == "__main__":
    sys.exit(main())
