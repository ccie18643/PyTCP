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
This module contains the IPv6 Destination Options protocol base class.

net_proto/protocols/ip6_dest_opts/ip6_dest_opts__base.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.proto import Proto
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__header import (
    Ip6DestOptsHeader,
    Ip6DestOptsHeaderProperties,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__options import Ip6DestOptsOptions


class Ip6DestOpts(Proto, Ip6DestOptsHeaderProperties):
    """
    The IPv6 Destination Options protocol base.
    """

    _header: Ip6DestOptsHeader
    _options: Ip6DestOptsOptions
    _payload: Buffer

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Dest Opts packet length (header + options + payload).
        """

        return len(self._header) + len(self._options) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 Dest Opts packet log string.
        """

        return (
            f"IPv6_DESTOPTS next {self._header.next}, "
            f"hdr_ext_len {self._header.hdr_ext_len} "
            f"({(self._header.hdr_ext_len + 1) * 8} bytes), "
            f"options [{self._options}]"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 Dest Opts packet representation string.
        """

        return (
            f"{type(self).__name__}(header={self._header!r}, " f"options={self._options!r}, payload={self._payload!r})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Dest Opts packet as a memoryview.
        """

        buffer = bytearray(self._header)
        buffer += bytearray(self._options)
        buffer += self._payload

        return memoryview(buffer)

    @property
    def header(self) -> Ip6DestOptsHeader:
        """
        Get the IPv6 Dest Opts packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> Ip6DestOptsOptions:
        """
        Get the IPv6 Dest Opts packet '_options' attribute.
        """

        return self._options

    @property
    def payload(self) -> Buffer:
        """
        Get the IPv6 Dest Opts packet '_payload' attribute.
        """

        return self._payload
