#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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
# misc/tx_status.py - module contains definition of TX Status codes
#


from __future__ import annotations  # Required by Python ver < 3.10

from enum import Enum, auto


class TxStatus(Enum):
    """TX Error codes"""

    PASSED_TO_TX_RING = auto()
    DROPED_ETHER_NO_GATEWAY = auto()
    DROPED_ETHER_CACHE_FAIL = auto()
    DROPED_ETHER_GATEWAY_CACHE_FAIL = auto()
    DROPED_ETHER_RESOLUTION_FAIL = auto()
    DROPED_IP4_NO_PROTOCOL_SUPPORT = auto()
    DROPED_IP4_INVALID_SOURCE = auto()
    DROPED_IP4_INVALID_DESTINATION = auto()
    DROPED_IP4_UNKNOWN = auto()
    DROPED_IP6_NO_PROTOCOL_SUPPORT = auto()
    DROPED_IP6_INVALID_SOURCE = auto()
    DROPED_IP6_INVALID_DESTINATION = auto()
    DROPED_IP6_EXT_FRAG_UNKNOWN = auto()
    DROPED_UDP_UNKNOWN = auto()
    DROPED_TCP_UNKNOWN = auto()
    DROPED_ICMP4_UNKNOWN = auto()
    DROPED_ICMP6_UNKNOWN = auto()

    def __str__(self) -> str:
        return str(self.name)
