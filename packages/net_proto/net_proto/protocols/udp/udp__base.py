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
This module contains the UDP protocol base class.

net_proto/protocols/udp/udp__base.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto import Proto
from net_proto.protocols.udp.udp__header import UdpHeader, UdpHeaderProperties


class Udp(Proto, UdpHeaderProperties):
    """
    The UDP protocol base.
    """

    _header: UdpHeader
    _payload: Buffer

    pshdr_sum: int = 0
    # RFC 6935 §5 zero-checksum opt-in flag. Class-level
    # default False so the standard RFC 768 substitution path
    # runs. The UDP assembler overrides per-instance when the
    # originating socket has 'UDP_NO_CHECK6_TX' set; the
    # parser never sets this attribute (parsed packets carry
    # their own '_header.cksum' wire value).
    _udp__no_cksum: bool = False

    @override
    def __len__(self) -> int:
        """
        Get the UDP packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the UDP packet log string.
        """

        return (
            f"UDP {self._header.sport} > {self._header.dport}, "
            f"len {self._header.plen} "
            f"({len(self._header)}+{self._header.plen - len(self._header)})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the UDP packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the UDP packet as a memoryview.
        """

        buffer = bytearray(self._header)
        buffer += self._payload
        if self._udp__no_cksum:
            # RFC 6935 §5 alternative mode: emit the literal
            # value 0x0000.
            buffer[6:8] = b"\x00\x00"
        else:
            # RFC 768: a computed checksum of zero is
            # transmitted as all-ones so the wire value
            # 0x0000 remains unambiguously the "no checksum
            # generated" sentinel.
            cksum = inet_cksum(buffer, init=self.pshdr_sum)
            buffer[6:8] = (cksum or 0xFFFF).to_bytes(2)

        return memoryview(buffer)

    @property
    def header(self) -> UdpHeader:
        """
        Get the UDP packet '_header' attribute.
        """

        return self._header

    @property
    def payload(self) -> Buffer:
        """
        Get the UDP packet '_payload' attribute.
        """

        return self._payload
