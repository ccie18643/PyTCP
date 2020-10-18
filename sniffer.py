#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
sniffer.py - tool used to test protocol handler classes

"""

import sys
import socket

import ph_ether
import ph_arp
import ph_ip
import ph_icmp
import ph_udp

# import ph_tcp

raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


def main():
    while True:
        raw_packet_rx = raw_socket.recv(2048)
        ether_packet_rx = ph_ether.EtherPacketRx(raw_packet_rx)

        if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_IP:
            ip_packet_rx = ph_ip.IpPacketRx(ether_packet_rx)

            if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_ICMP:
                icmp_packet_rx = ph_icmp.IcmpPacketRx(ip_packet_rx)
                print(ether_packet_rx.dump)
                print(ip_packet_rx.dump)
                print(icmp_packet_rx.dump)
                print("-" * 80)

            if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_UDP:
                udp_packet_rx = ph_udp.UdpPacketRx(ip_packet_rx)
                print(ether_packet_rx.dump)
                print(ip_packet_rx.dump)
                print(udp_packet_rx.dump)
                print("-" * 80)


if __name__ == "__main__":
    sys.exit(main())
