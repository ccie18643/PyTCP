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
This module contains IPv6 wildcard support class.

net_addr/ip6_wildcard.py

ver 3.0.8
"""

import socket
from typing import Self, final, override

from net_addr.errors import Ip6WildcardFormatError
from net_addr.ip6_address import IP6__ADDRESS_LEN, IP6__MASK
from net_addr.ip_version import IpVersion
from net_addr.ip_wildcard import IpWildcard


@final
class Ip6Wildcard(IpWildcard):
    """
    IPv6 wildcard support class.

    Any in-range 128-bit value is a valid wildcard (arbitrary,
    possibly non-contiguous bits) — ACL / firewall semantics.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6

    def __init__(
        self,
        wildcard: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv6 wildcard object.
        """

        if wildcard is None:
            self._wildcard = 0
            return

        if isinstance(wildcard, Ip6Wildcard):
            self._wildcard = int(wildcard)
            return

        if isinstance(wildcard, int):
            if 0 <= wildcard <= IP6__MASK:
                self._wildcard = wildcard
                return

        if isinstance(wildcard, (memoryview, bytes, bytearray)):
            if len(wildcard) == IP6__ADDRESS_LEN:
                self._wildcard = int.from_bytes(wildcard)
                return

        if isinstance(wildcard, str):
            # Surrounding whitespace is stripped uniformly across
            # every net_addr string constructor. 'socket.inet_pton'
            # is the strict POSIX parser and the sole validator
            # (mirrors the IPv4 wildcard constructor); no
            # pre-filter regex.
            text = wildcard.strip()
            try:
                self._wildcard = int.from_bytes(socket.inet_pton(socket.AF_INET6, text))
                return
            except OSError:
                pass

        raise Ip6WildcardFormatError(wildcard)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 wildcard log string.
        """

        return socket.inet_ntop(socket.AF_INET6, bytes(self))

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 wildcard as a memoryview.
        """

        return memoryview(bytearray(self._wildcard.to_bytes(IP6__ADDRESS_LEN)))
