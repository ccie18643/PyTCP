#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
stack.py - module holds refeences to the stack components

"""

mtu = 1500

local_tcp_mss = 1460  # Maximum segment peer can send to us
local_tcp_win = 65535  # Maximum amount of data peer can send to us without confirmation


rx_ring = None
tx_ring = None
arp_cache = None
icmpv6_nd_cache = None
packet_handler = None
tcp_sessions = {}
udp_sockets = {}
