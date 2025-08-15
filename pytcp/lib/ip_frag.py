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
Module contains classes used for IPv4/IPv6 packet fragmentation and reassembly.

pytcp/lib/ip_frag.py

ver 3.0.3
"""


from __future__ import annotations

import time
from dataclasses import dataclass, field

from net_addr.ip_address import IpAddress


@dataclass(kw_only=True, frozen=True)
class IpFragFlowId:
    """
    Class stores IPv4/IPv6 packet fragmentation flow ID.
    """

    src: IpAddress
    dst: IpAddress
    id: int


@dataclass(kw_only=True)
class IpFragData:
    """
    Class stores IPv4/IPv6 packet fragmentation data.
    """

    timestamp: float = field(default_factory=time.time, init=False)
    header: bytes
    last: bool = field(default=False, init=False)
    payload: dict[int, bytes]
