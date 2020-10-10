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

raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


def main():
    while True:
        data = raw_socket.recv(2048)

        data = data[14:]

        ip_hdr = IpHeader()
        ip_hdr.read(data)
        data = data[ip_hdr.hlen:]
   
        tcp_hdr = TcpHeader()
        tcp_hdr.read(data)
        data = data[tcp_hdr.hlen:]

        if tcp_hdr.dport == 7000:
            print(ip_hdr)
            print(tcp_hdr)
            print("-" * 80)

        '''
            print(f"{ip_hdr.src}:{tcp_hdr.sport} -> {ip_hdr.dst}:{tcp_hdr.dport} " + 
                  f"{'URG ' if tcp_hdr.flag_urg else ''}" + 
                  f"{'ACK ' if tcp_hdr.flag_ack else ''}" + 
                  f"{'PSH ' if tcp_hdr.flag_psh else ''}" + 
                  f"{'RST ' if tcp_hdr.flag_rst else ''}" + 
                  f"{'SYN ' if tcp_hdr.flag_syn else ''}" + 
                  f"{'FIN ' if tcp_hdr.flag_fin else ''}"
            )
        '''


if __name__ == "__main__":
    sys.exit(main())
