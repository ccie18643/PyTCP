#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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


#
# __init__.py
#
# ver 2.7
#


import fcntl
import os
import struct
import sys

import pytcp.misc.stack as stack
from pytcp.lib.logger import log

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


class TcpIpStack:
    """
    Main PyTCP library class.
    """

    def __init__(self, interface: str):
        """
        Initialize stack on given interface.
        """

        try:
            self.tap = os.open("/dev/net/tun", os.O_RDWR)

        except FileNotFoundError:
            log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
            sys.exit(-1)

        fcntl.ioctl(
            self.tap,
            TUNSETIFF,
            struct.pack("16sH", interface.encode(), IFF_TAP | IFF_NO_PI),
        )

    def start(self) -> None:
        """
        Start stack components.
        """
        stack.timer.start()
        stack.arp_cache.start()
        stack.nd_cache.start()
        stack.rx_ring.start(self.tap)
        stack.tx_ring.start(self.tap)
        stack.packet_handler.start()
        stack.packet_handler.assign_ip6_addresses()
        stack.packet_handler.assign_ip4_addresses()
        stack.packet_handler.log_stack_address_info()

    def stop(self) -> None:
        """
        Stop stack components.
        """
        stack.packet_handler.stop()
        stack.tx_ring.stop()
        stack.rx_ring.stop()
        stack.arp_cache.stop()
        stack.nd_cache.stop()
        stack.timer.stop()
