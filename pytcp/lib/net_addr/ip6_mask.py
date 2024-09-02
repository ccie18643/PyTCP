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
Module contains IPv6 mask support class.

pytcp/lib/net_addr/ip6_mask.py

ver 3.0.2
"""


from __future__ import annotations

import re
import socket
from typing import override

from pytcp.lib.net_addr.ip6_address import IP6__ADDRESS_LEN

from .errors import Ip6MaskFormatError
from .ip_mask import IpMask


class Ip6Mask(IpMask):
    """
    IPv6 network mask support class.
    """

    _version: int = 6

    def __init__(
        self,
        /,
        mask: (
            Ip6Mask | str | bytes | bytearray | memoryview | int | None
        ) = None,
    ) -> None:
        """
        Create a new IPv6 mask object.
        """

        if mask is None:
            self._mask = 0
            return

        if isinstance(mask, int):
            if mask & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF == mask:
                self._mask = mask
                if self._validate_bits(IP6__ADDRESS_LEN * 8):
                    return

        if isinstance(mask, (memoryview, bytes, bytearray)):
            if len(mask) == 16:
                self._mask = int.from_bytes(mask)
                if self._validate_bits(IP6__ADDRESS_LEN * 8):
                    return

        if isinstance(mask, str) and re.search(r"^\/\d{1,3}$", mask):
            bit_count = int(mask[1:])
            if bit_count in range(129):
                self._mask = int("1" * bit_count + "0" * (128 - bit_count), 2)
                return

        if isinstance(mask, Ip6Mask):
            self._mask = mask._mask
            return

        raise Ip6MaskFormatError(mask)

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 mask string representation.
        """

        return f"{self.__class__.__name__}('{socket.inet_ntop(socket.AF_INET6, bytes(self))}')"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv6 mask as bytes.
        """

        return self._mask.to_bytes(16)
