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
This module contains IPv6 mask support class.

net_addr/ip6_mask.py

ver 3.0.9
"""

import re
from typing import Self, final, override

from net_addr.buffer import Buffer
from net_addr.errors import Ip6MaskFormatError
from net_addr.ip6_address import IP6__ADDRESS_LEN, IP6__MASK
from net_addr.ip_mask import IpMask
from net_addr.ip_version import IpVersion


@final
class Ip6Mask(IpMask):
    """
    IPv6 network mask support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6

    def __init__(
        self,
        mask: Self | str | Buffer | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv6 mask object.
        """

        if mask is None:
            self._mask = 0
            return

        if isinstance(mask, Ip6Mask):
            self._mask = int(mask)
            return

        if isinstance(mask, int):
            if 0 <= mask <= IP6__MASK and self._is_contiguous_mask(mask, IP6__ADDRESS_LEN * 8):
                self._mask = mask
                return

        if isinstance(mask, (memoryview, bytes, bytearray)):
            if len(mask) == IP6__ADDRESS_LEN:
                candidate = int.from_bytes(mask)
                if self._is_contiguous_mask(candidate, IP6__ADDRESS_LEN * 8):
                    self._mask = candidate
                    return

        if isinstance(mask, str):
            # Surrounding whitespace is stripped uniformly across
            # every net_addr string constructor.
            text = mask.strip()
            if re.search(r"^/(0|[1-9][0-9]{0,2})$", text):
                bit_count = int(text[1:])
                if 0 <= bit_count <= IP6__ADDRESS_LEN * 8:
                    self._mask = ((1 << bit_count) - 1) << (IP6__ADDRESS_LEN * 8 - bit_count)
                    return

        raise Ip6MaskFormatError(mask)

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 mask as a memoryview.
        """

        return memoryview(bytearray(self._mask.to_bytes(IP6__ADDRESS_LEN)))
