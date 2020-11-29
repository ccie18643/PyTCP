#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# sniffer.py - tool used to test protocol handler classes
#


import socket
import sys

import ps_arp
import ps_ether
import ps_icmp4
import ps_icmp6
import ps_ip4
import ps_ip6
import ps_tcp
import ps_udp

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

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP6:
            ip6_packet_rx = ps_ip6.Ip6Packet(ether_packet_rx)

            if ip6_packet_rx.ip6_next == ps_ip6.IP6_NEXT_HEADER_ICMP6:
                icmp6_packet_rx = ps_icmp6.Icmp6Packet(ip6_packet_rx)
                print("-" * 160)
                print(ether_packet_rx)
                print(ip6_packet_rx)
                print(icmp6_packet_rx)
                print("-" * 160)
                continue

            print("-" * 160)
            print(ether_packet_rx)
            print(ip6_packet_rx)
            continue

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP6:
            ip4_packet_rx = ps_ip4.Ip4Packet(ether_packet_rx)

            if ip4_packet_rx.ip4_proto == ps_ip4.IP4_PROTO_ICMP4:
                icmp4_packet_rx = ps_icmp4.Icmp4Packet(ip4_packet_rx)
                print("-" * 160)
                print(ether_packet_rx)
                print(ip4_packet_rx)
                print(icmp4_packet_rx)
                print("-" * 160)
                continue

            if ip4_packet_rx.ip4_proto == ps_ip4.IP4_PROTO_UDP:
                udp_packet_rx = ps_udp.UdpPacket(ip4_packet_rx)
                print("-" * 160)
                print(ether_packet_rx)
                print(ip4_packet_rx)
                print(udp_packet_rx)
                print("-" * 160)
                continue

            if ip4_packet_rx.ip4_proto == ps_ip4.IP4_PROTO_TCP:
                tcp_packet_rx = ps_tcp.TcpPacket(ip4_packet_rx)
                if 22 in {tcp_packet_rx.tcp_dport, tcp_packet_rx.tcp_sport}:
                    continue
                print("-" * 160)
                print(ether_packet_rx)
                print(ip4_packet_rx)
                print(tcp_packet_rx)
                print("-" * 160)
                continue

            print("-" * 160)
            print(ether_packet_rx)
            print(ip4_packet_rx)
            print("-" * 160)
            continue

        print("-" * 160)
        print(ether_packet_rx)


if __name__ == "__main__":
    sys.exit(main())
