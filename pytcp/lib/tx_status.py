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


"""
Module contains definition of TX status codes.

pytcp/lib/tx_status.py

ver 2.7
"""


from __future__ import annotations

from enum import Enum, auto


class TxStatus(Enum):
    """
    TX status codes.
    """

    PASSED__ETHER__TO_TX_RING = auto()

    DROPED__ETHER__DST_ARP_CACHE_FAIL = auto()
    DROPED__ETHER__DST_ND_CACHE_FAIL = auto()
    DROPED__ETHER__DST_NO_GATEWAY_IP4 = auto()
    DROPED__ETHER__DST_NO_GATEWAY_IP6 = auto()
    DROPED__ETHER__DST_GATEWAY_ARP_CACHE_FAIL = auto()
    DROPED__ETHER__DST_GATEWAY_ND_CACHE_FAIL = auto()
    DROPED__ETHER__DST_RESOLUTION_FAIL = auto()

    DROPED__ARP__NO_PROTOCOL_SUPPORT = auto()

    DROPED__IP4__NO_PROTOCOL_SUPPORT = auto()
    DROPED__IP4__SRC_NOT_OWNED = auto()
    DROPED__IP4__SRC_MULTICAST = auto()
    DROPED__IP4__SRC_LIMITED_BROADCAST = auto()
    DROPED__IP4__SRC_NETWORK_BROADCAST = auto()
    DROPED__IP4__SRC_UNSPECIFIED = auto()
    DROPED__IP4__DST_UNSPECIFIED = auto()
    DROPED__IP4__UNKNOWN = auto()

    DROPED__IP6__NO_PROTOCOL_SUPPORT = auto()
    DROPED__IP6__SRC_NOT_OWNED = auto()
    DROPED__IP6__SRC_MULTICAST = auto()
    DROPED__IP6__SRC_LIMITED_BROADCAST = auto()
    DROPED__IP6__SRC_NETWORK_BROADCAST = auto()
    DROPED__IP6__SRC_UNSPECIFIED = auto()
    DROPED__IP6__DST_UNSPECIFIED = auto()
    DROPED__IP6__UNKNOWN = auto()

    DROPED__IP6__EXT_FRAG_UNKNOWN = auto()

    DROPED__UDP__UNKNOWN = auto()

    DROPED__TCP__UNKNOWN = auto()

    DROPED__ICMP4__UNKNOWN = auto()

    DROPED__ICMP6__UNKNOWN = auto()

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """
        return str(self.name)

    def __eq__(self, other: object) -> bool:
        """
        The '__eq__()' dunder.
        """
        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        The '__hash__()' dunder.
        """
        return hash(repr)
