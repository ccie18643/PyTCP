#!/usr/bin/env python3

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
Module holds references to the stack components and global structures.

pytcp/stack.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pytcp.stack.arp_cache import ArpCache
from pytcp.stack.nd_cache import NdCache
from pytcp.stack.packet_handler import PacketHandler
from pytcp.stack.rx_ring import RxRing
from pytcp.stack.timer import Timer
from pytcp.stack.tx_ring import TxRing

if TYPE_CHECKING:
    from net_addr import Ip4Address
    from pytcp.socket.socket import Socket


version_string = "ver 3.0.2"
github_repository = "https://github.com/ccie18643/PyTCP"

timer = Timer()
rx_ring = RxRing()
tx_ring = TxRing()
arp_cache = ArpCache()
nd_cache = NdCache()
packet_handler = PacketHandler()

sockets: dict[tuple[Any, ...], Socket] = {}
arp_probe_unicast_conflict: set[Ip4Address] = set()
