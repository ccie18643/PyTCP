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
# ph_speed_test.py - test measuring the speed of FPP and FPA
#
# ver 2.7
#


from __future__ import annotations

import time

from lib.ip4_address import Ip4Host
from lib.ip6_address import Ip6Host
from lib.mac_address import MacAddress
from misc.packet import PacketRx
from misc.ph import PacketHandler


class ArpCache:
    """
    Mock class.
    """

    def __init__(self):
        """
        Class constructor.
        """
        self._response = MacAddress("52:54:00:df:85:37")

    def find_entry(self, _):
        """
        Return the predefined MAC Address entry.
        """
        return self._response


class NdCache:
    """
    Mock class.
    """

    def __init__(self):
        """
        Class constructor.
        """
        self._response = MacAddress("52:54:00:df:85:37")

    def find_entry(self, _):
        """
        Return the predefined MAC Address entry.
        """
        return self._response


class TxRing:
    """Mock class"""

    def __init__(self):
        """
        Class constructor.
        """
        self.packet_count = 0
        self.frame = memoryview(bytearray(2048))

    def enqueue(self, packet_rx):
        """
        Assemble packed and update packet counter.
        """
        packet_rx.assemble(self.frame)
        self.packet_count += 1
        return None


def main():
    """
    Main program function.
    """

    with open("tests/ping4.frame_rx", "rb") as f:
        frame_rx = f.read()

    packet_handler = PacketHandler(None)
    packet_handler.arp_cache = ArpCache()
    packet_handler.nd_cache = NdCache()
    packet_handler.tx_ring = TxRing()
    packet_handler.ip4_host = [Ip4Host("192.168.9.7/24")]
    packet_handler.ip6_host = [Ip6Host("2603:9000:e307:9f09:0:ff:fe77:7777/64")]

    if __debug__:
        print()
        packet_handler._phrx_ether(PacketRx(frame_rx))
        print()
        print("****************************************")
        print("*                                      *")
        print("* Run as 'python -OO ph_speed_test.py' *")
        print("*                                      *")
        print("****************************************")
        print()
        return

    start_time = time.time()
    for _ in range(10000):
        packet_handler._phrx_ether(PacketRx(frame_rx))
    print(
        f"{packet_handler.tx_ring.packet_count} packets, "
        f"{time.time() - start_time:.03f}s"
    )


if __name__ == "__main__":
    main()
