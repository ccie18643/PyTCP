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
# stack.py - module holds references to the stack components and global structures
#

import config


class Stack:
    """ Class containing stack's global variables """

    def __init__(self):
        """ Class constructor """

        # References to stack components
        self.rx_ring = None
        self.tx_ring = None
        self.arp_cache = None
        self.icmp6_nd_cache = None
        self.packet_handler = None
        self.timer = None

        # Stack 'global variables'
        self.mac_unicast = config.mac_address
        self.mac_multicast = []
        self.mac_broadcast = "ff:ff:ff:ff:ff:ff"
        self.ip6_address = []
        self.ip6_multicast = []
        self.ip4_address = []
        self.ip4_multicast = []
        self.tcp_sessions = {}
        self.udp_sockets = {}

    @property
    def ip6_unicast(self):
        """ Return list of stack's IPv6 unicast addresses """

        return [_.ip for _ in stack.ip6_address]

    @property
    def ip4_unicast(self):
        """ Return list of stack's IPv4 unicast addresses """

        return [_.ip for _ in stack.ip4_address]

    @property
    def ip4_broadcast(self):
        """ Return list of stack's IPv4 broadcast addresses """

        ip4_broadcast = [_.network.broadcast_address for _ in stack.ip4_address]
        ip4_broadcast.append("255.255.255.255")
        return ip4_broadcast


stack = Stack()
