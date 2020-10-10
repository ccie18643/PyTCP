#!/usr/bin/env python3

import socket
import struct
import binascii

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

while True:
    pkt = rawSocket.recvfrom(2048)

    ipHeader = pkt[0][14:34]
    ip_hdr = struct.unpack("!12s4s4s", ipHeader)
    tcpHeader = pkt[0][34:54]
    tcp_hdr = struct.unpack("!HH16s", tcpHeader)

    if tcp_hdr[1] == 7000 or tcp_hdr[0] == 7000:
        print()
        print("Source IP address %s" % socket.inet_ntoa(ip_hdr[1]))
        print("Destination IP address %s" % socket.inet_ntoa(ip_hdr[2]))
        print("Source Port: %s" % tcp_hdr[0])
        print("Destination Port: %s" % tcp_hdr[1])
