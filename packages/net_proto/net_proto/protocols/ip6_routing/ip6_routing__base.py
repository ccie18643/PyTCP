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
This module contains the IPv6 Routing Header protocol base class.

net_proto/protocols/ip6_routing/ip6_routing__base.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.proto import Proto
from net_proto.protocols.ip6_routing.ip6_routing__header import (
    Ip6RoutingHeader,
    Ip6RoutingHeaderProperties,
)


class Ip6Routing(Proto, Ip6RoutingHeaderProperties):
    """
    The IPv6 Routing Header protocol base.
    """

    _header: Ip6RoutingHeader
    _data: bytes
    _payload: Buffer

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Routing packet length (fixed prefix +
        type-specific data + payload).
        """

        return len(self._header) + len(self._data) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 Routing packet log string.
        """

        return (
            f"IPv6_ROUTING type {self._header.routing_type}, "
            f"segments_left {self._header.segments_left}, "
            f"next {self._header.next}, "
            f"hdr_ext_len {self._header.hdr_ext_len} "
            f"({(self._header.hdr_ext_len + 1) * 8} bytes), "
            f"data_len {len(self._data)}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 Routing packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, " f"data={self._data!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Routing packet as a memoryview.
        """

        buffer = bytearray(self._header)
        buffer += self._data
        buffer += self._payload

        return memoryview(buffer)

    @property
    def header(self) -> Ip6RoutingHeader:
        """
        Get the IPv6 Routing packet '_header' attribute.
        """

        return self._header

    @property
    def data(self) -> bytes:
        """
        Get the IPv6 Routing packet '_data' attribute (the
        type-specific data block following the fixed 4-byte
        prefix; preserved byte-for-byte for Phase-2 forwarder
        re-emission).
        """

        return self._data

    @property
    def payload(self) -> Buffer:
        """
        Get the IPv6 Routing packet '_payload' attribute.
        """

        return self._payload
