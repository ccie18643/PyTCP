#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
sniffer.py - tool used to test protocol handler classes

"""

import sys
import socket
import struct
import binascii

import ph_ethernet
import ph_arp
import ph_ip
#import ph_tcp

raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


def main():
    while True:
        raw_packet = raw_socket.recv(2048)
        ethernet_packet = ph_ethernet.EthernetPacket(raw_packet)
        print(ethernet_packet.dump)

        if ethernet_packet.ethertype == ph_ethernet.ETHERTYPE_IP:
            ip_packet = ph_ip.IpPacket(ethernet_packet.raw_data)
            print(ip_packet.dump)

            '''
            if ip_packet.proto == ph_ip.IP_PROTO_TCP:
                tcp_packet = ph_tcp.TcpPacket(ip_packet)
                print(repr(tcp_packet))
            '''

        print("-" * 80)


if __name__ == "__main__":
    sys.exit(main())
