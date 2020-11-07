#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
stack.py - module holds refeences to the stack components

"""

rx_ring = None
tx_ring = None
arp_cache = None
packet_handler = None
open_sockets = {}
