#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
sniffer.py - tool used to test protocol handler classes

"""

import sys
import socket
import struct
import binascii

from ip_header import IpHeader
from tcp_header import TcpHeader
from ethernet_header import EthernetHeader

raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


def main():
    while True:
        data = raw_socket.recv(2048)
        eth_hdr = EthernetHeader(data[:14])
        data = data[14:]

        ip_hdr = IpHeader(data)
        data = data[ip_hdr.header_length:]

        if ip_hdr.protocol == 6:
            tcp_hdr = TcpHeader(data, ip_hdr.get_ip_pseudo_header())
            data = data[tcp_hdr.data_offset:]

            if tcp_hdr.destination_port == 22:
                print(eth_hdr)
                print(ip_hdr)
                print(tcp_hdr)
                print("-" * 80)


if __name__ == "__main__":
    sys.exit(main())
