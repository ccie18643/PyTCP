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
This module contains IPv4 wildcard support class.

net_addr/ip4_wildcard.py

ver 3.0.10
"""

import socket
from typing import Self, final, override

from net_addr.buffer import Buffer
from net_addr.errors import Ip4WildcardFormatError
from net_addr.ip4_address import IP4__ADDRESS_LEN, IP4__MASK
from net_addr.ip_version import IpVersion
from net_addr.ip_wildcard import IpWildcard


@final
class Ip4Wildcard(IpWildcard):
    """
    IPv4 wildcard support class.

    Any in-range 32-bit value is a valid wildcard (arbitrary,
    possibly non-contiguous bits) — Cisco/ACL semantics.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    def __init__(
        self,
        wildcard: Self | str | Buffer | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 wildcard object.
        """

        if wildcard is None:
            self._wildcard = 0
            return

        if isinstance(wildcard, Ip4Wildcard):
            self._wildcard = int(wildcard)
            return

        if isinstance(wildcard, int):
            if 0 <= wildcard <= IP4__MASK:
                self._wildcard = wildcard
                return

        if isinstance(wildcard, (memoryview, bytes, bytearray)):
            if len(wildcard) == IP4__ADDRESS_LEN:
                self._wildcard = int.from_bytes(wildcard)
                return

        if isinstance(wildcard, str):
            # Surrounding whitespace is stripped uniformly across
            # every net_addr string constructor. 'socket.inet_pton'
            # is the strict POSIX parser; the legacy
            # 'socket.inet_aton' would accept octal / hex octets and
            # leading zeros and silently reinterpret the dotted
            # wildcard.
            try:
                self._wildcard = int.from_bytes(socket.inet_pton(socket.AF_INET, wildcard.strip()))
                return
            except OSError:
                pass

        raise Ip4WildcardFormatError(wildcard)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 wildcard log string.
        """

        return socket.inet_ntoa(bytes(self))

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 wildcard as a memoryview.
        """

        return memoryview(bytearray(self._wildcard.to_bytes(IP4__ADDRESS_LEN)))
