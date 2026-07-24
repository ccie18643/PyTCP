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
This module contains the IPv6 Hop-by-Hop Options protocol base class.

net_proto/protocols/ip6_hbh/ip6_hbh__base.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.proto import Proto
from net_proto.protocols.ip6_hbh.ip6_hbh__header import (
    Ip6HbhHeader,
    Ip6HbhHeaderProperties,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions


class Ip6Hbh(Proto, Ip6HbhHeaderProperties):
    """
    The IPv6 Hop-by-Hop Options protocol base.
    """

    _header: Ip6HbhHeader
    _options: Ip6HbhOptions
    _payload: Buffer

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 HBH packet length (header + options + payload).
        """

        return len(self._header) + len(self._options) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 HBH packet log string.
        """

        return (
            f"IPv6_HBH next {self._header.next}, "
            f"hdr_ext_len {self._header.hdr_ext_len} "
            f"({(self._header.hdr_ext_len + 1) * 8} bytes), "
            f"options [{self._options}]"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 HBH packet representation string.
        """

        return (
            f"{type(self).__name__}(header={self._header!r}, " f"options={self._options!r}, payload={self._payload!r})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 HBH packet as a memoryview.
        """

        buffer = bytearray(self._header)
        buffer += bytearray(self._options)
        buffer += self._payload

        return memoryview(buffer)

    @property
    def header(self) -> Ip6HbhHeader:
        """
        Get the IPv6 HBH packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> Ip6HbhOptions:
        """
        Get the IPv6 HBH packet '_options' attribute.
        """

        return self._options

    @property
    def payload(self) -> Buffer:
        """
        Get the IPv6 HBH packet '_payload' attribute.
        """

        return self._payload
