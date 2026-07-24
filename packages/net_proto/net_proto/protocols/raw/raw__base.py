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
This module contains the Raw protocol base class.

net_proto/protocols/raw/raw__base.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto import Proto


class Raw(Proto):
    """
    The Raw protocol base.
    """

    _payload: Buffer

    _ether_type: EtherType
    _ip_proto: IpProto

    pshdr_sum: int = 0

    @override
    def __len__(self) -> int:
        """
        Get the Raw packet length.
        """

        return len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the Raw packet log string.
        """

        return f"Raw, len {len(self)}"

    @override
    def __repr__(self) -> str:
        """
        Get the Raw packet representation string.
        """

        return f"{type(self).__name__}(raw__payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the Raw packet as a memoryview.
        """

        buffer = bytearray(self._payload)

        # ICMPv6 raw sockets: the kernel ALWAYS computes and inserts
        # the ICMPv6 checksum, overwriting whatever the application
        # supplied (RFC 3542 §3.1 — the checksum is mandatory and
        # covers the IPv6 pseudo-header, which the application does
        # not control; Linux forces it on for IPPROTO_ICMPV6 raw
        # sockets unconditionally). Zero the field before summing so
        # an app-supplied value cannot poison the result. A payload
        # too short to hold the 2-byte checksum at offset 2 is left
        # untouched (a malformed ICMPv6 message has no checksum slot).
        if self._ip_proto == IpProto.ICMP6 and len(buffer) >= 4:
            buffer[2:4] = b"\x00\x00"
            buffer[2:4] = inet_cksum(buffer, init=self.pshdr_sum).to_bytes(2)

        # ICMPv4 (and every other) raw payload is emitted verbatim:
        # Linux SOCK_RAW / IPPROTO_ICMP does NOT compute the IPv4
        # transport checksum — the application owns it. (See
        # 'examples/client__icmp_echo.py', which computes its own
        # ICMPv4 checksum accordingly.)

        return memoryview(buffer)

    @property
    def payload(self) -> Buffer:
        """
        Get the Raw packet '_payload' attribute.
        """

        return self._payload

    @property
    def ether_type(self) -> EtherType:
        """
        Get the Raw packet '_ether_type' attribute.
        """

        return self._ether_type

    @property
    def ip_proto(self) -> IpProto:
        """
        Get the Raw packet '_ip_proto' attribute.
        """

        return self._ip_proto
