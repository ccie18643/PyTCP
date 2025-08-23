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
This module contains classes used in the IPv4/IPv6 packet fragmentation and reassembly
processes.

pytcp/lib/ip_frag.py

ver 3.0.3
"""


import time
from dataclasses import dataclass, field

from net_addr import Ip4Address, Ip6Address


@dataclass(kw_only=True, frozen=True, slots=True)
class IpFragFlowId:
    """
    Class stores the IPv4/IPv6 packet fragmentation flow ID.
    """

    src: Ip6Address | Ip4Address
    dst: Ip6Address | Ip4Address
    id: int


@dataclass(kw_only=True, frozen=True, slots=True)
class IpFragData:
    """
    Class stores the IPv4/IPv6 packet fragmentation data.
    """

    timestamp: float = field(default_factory=time.time, init=False)
    header: bytes
    last: bool = field(default=False, init=False)
    payload: dict[int, bytes]

    def received_last_frag(self) -> None:
        """
        Set the last fragment flag.
        """

        object.__setattr__(self, "last", True)
