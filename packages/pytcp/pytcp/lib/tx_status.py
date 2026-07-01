################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the definition of the TX status codes.

pytcp/lib/tx_status.py

ver 3.0.8
"""

from enum import auto

from pytcp.lib.name_enum import NameEnum


class TxStatus(NameEnum):
    """
    The TX status codes.
    """

    PASSED__ETHERNET__TO_TX_RING = auto()

    DROPPED__ETHERNET__DST_ARP_CACHE_MISS = auto()
    DROPPED__ETHERNET__DST_ND_CACHE_MISS = auto()
    DROPPED__ETHERNET__DST_NO_GATEWAY_IP4 = auto()
    DROPPED__ETHERNET__DST_NO_GATEWAY_IP6 = auto()
    DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS = auto()
    DROPPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS = auto()
    DROPPED__ETHERNET__DST_RESOLUTION_FAIL = auto()

    PASSED__ETHERNET_802_3__TO_TX_RING = auto()

    DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL = auto()

    DROPPED__ARP__NO_PROTOCOL_SUPPORT = auto()

    PASSED__IP4__TO_TX_RING = auto()
    PASSED__IP4__LOOPBACK = auto()

    DROPPED__IP4__NO_PROTOCOL_SUPPORT = auto()
    DROPPED__IP4__SRC_NOT_OWNED = auto()
    DROPPED__IP4__SRC_MULTICAST = auto()
    DROPPED__IP4__SRC_LIMITED_BROADCAST = auto()
    DROPPED__IP4__SRC_NETWORK_BROADCAST = auto()
    DROPPED__IP4__SRC_UNSPECIFIED = auto()
    DROPPED__IP4__DST_UNSPECIFIED = auto()
    DROPPED__IP4__MTU_EXCEED_DF = auto()
    DROPPED__IP4__UNKNOWN = auto()

    PASSED__IP6__TO_TX_RING = auto()
    PASSED__IP6__LOOPBACK = auto()

    DROPPED__IP6__NO_PROTOCOL_SUPPORT = auto()
    DROPPED__IP6__SRC_NOT_OWNED = auto()
    DROPPED__IP6__SRC_MULTICAST = auto()
    DROPPED__IP6__SRC_LIMITED_BROADCAST = auto()
    DROPPED__IP6__SRC_NETWORK_BROADCAST = auto()
    DROPPED__IP6__SRC_UNSPECIFIED = auto()
    DROPPED__IP6__SRC_SCOPE_MISMATCH = auto()
    DROPPED__IP6__DST_UNSPECIFIED = auto()
    DROPPED__IP6__UNKNOWN = auto()

    DROPPED__IP6__EXT_FRAG_UNKNOWN = auto()
    DROPPED__IP6__ND_FRAGMENTATION_FORBIDDEN = auto()

    DROPPED__UDP__UNKNOWN = auto()

    DROPPED__TCP__UNKNOWN = auto()

    DROPPED__ICMP4__UNKNOWN = auto()

    DROPPED__ICMP6__UNKNOWN = auto()

    DROPPED__IP4__DST_BROADCAST_DISALLOWED = auto()

    DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH = auto()
