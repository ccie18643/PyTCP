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

# import ph_tcp

raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


def main():
    while True:
        raw_packet = raw_socket.recv(2048)
        ether_packet = ph_ether.EtherPacketRx(raw_packet)

        if ether_packet.hdr_type == ph_ether.ETHER_TYPE_IP:
            ip_packet = ph_ip.IpPacketRx(ether_packet.raw_data)

            if ip_packet.hdr_proto == ph_ip.IP_PROTO_ICMP:
                icmp_packet = ph_icmp.IcmpPacketRx(ip_packet.raw_data)
                print(ether_packet.dump)
                print(ip_packet.dump)
                print(icmp_packet.dump)
                print("-" * 80)

            """
            if ip_packet.proto == ph_ip.IP_PROTO_TCP:
                tcp_packet = ph_tcp.TcpPacket(ip_packet.raw_data)
                print(tcp_packet.dump)
            """


if __name__ == "__main__":
    sys.exit(main())
