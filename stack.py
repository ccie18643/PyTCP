#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
stack.py - module holds refeences to the stack components

"""

mtu = 1500
tcp_mss = 1460
tcp_win = 65535


rx_ring = None
tx_ring = None
arp_cache = None
packet_handler = None
tcp_sessions = {}
udp_sockets = {}
