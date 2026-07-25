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
This module contains the ICMPv6 MLDv1 Multicast Listener Query
message (type 130, 24-octet form) support class. A host parses an
inbound MLDv1 Query to enter MLDv1 compatibility mode (RFC 3810
§8.2.1); the Phase-2 querier assembles it to emit MLDv1-format
Queries under an older-version-querier-present interop. The MLDv1
Query is distinguished from the larger MLDv2 Query (>= 28 octets) by
its fixed 24-octet length (RFC 3810 §8.1).

net_proto/protocols/icmp6/message/mld1/icmp6__mld1__message__query.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    ICMP6__MLD1__MESSAGE__LEN,
    ICMP6__MLD1__MESSAGE__STRUCT,
)

# The ICMPv6 MLDv1 Multicast Listener Query message (130/0) [RFC 2710
# §3]. Shares the fixed 24-octet MLDv1 message layout (the field
# constants live in the Report module). The Multicast Address is the
# unspecified address (::) for a General Query, or the queried group
# for a Multicast-Address-Specific Query; Maximum Response Delay is the
# host's response-window bound in milliseconds. A 24-octet Query is the
# MLDv1 form — an MLDv2 Query is >= 28 octets (RFC 3810 §8.1).
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Maximum Response Delay     |          Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# *                       Multicast Address                       *
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class Icmp6Mld1QueryCode(Icmp6Code):
    """
    The ICMPv6 MLDv1 Query 'code' field values.
    """

    DEFAULT = 0  # RFC 2710 §3: the Code field is set to zero.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6Mld1MessageQuery(Icmp6Message):
    """
    The ICMPv6 MLDv1 Query message (24-octet form). A General Query
    carries the unspecified multicast address (::); a
    Multicast-Address-Specific Query carries the queried group. On RX
    the parser drives the MLDv1 compatibility timer; on TX the Phase-2
    querier assembles it under an older-version-querier interop.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.MULTICAST_LISTENER_QUERY,
    )
    code: Icmp6Mld1QueryCode = Icmp6Mld1QueryCode.DEFAULT
    cksum: int = 0

    maximum_response_delay: int = 0
    multicast_address: Ip6Address = Ip6Address()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv1 Query message fields.
        """

        assert isinstance(
            self.code, Icmp6Mld1QueryCode
        ), f"The 'code' field must be an Icmp6Mld1QueryCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert is_uint16(
            self.maximum_response_delay
        ), f"The 'maximum_response_delay' field must be uint16. Got: {self.maximum_response_delay!r}"

        assert isinstance(
            self.multicast_address, Ip6Address
        ), f"The 'multicast_address' field must be an Ip6Address. Got: {type(self.multicast_address)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 MLDv1 Query message length.
        """

        return ICMP6__MLD1__MESSAGE__LEN

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 MLDv1 Query message log string.
        """

        return f"ICMPv6 MLDv1 Query, mrd={self.maximum_response_delay}, " f"multicast {self.multicast_address}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 MLDv1 Query message as a memoryview, with the
        checksum slot left zero for the ICMPv6 base to inject.
        """

        return memoryview(self._pack_header())

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__MLD1__MESSAGE__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 MLDv1 Query fixed 24-octet header as bytes.
        """

        struct.pack_into(
            ICMP6__MLD1__MESSAGE__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            self.maximum_response_delay,
            0,
            bytes(self.multicast_address),
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 MLDv1 Query message after parsing
        it. The Hop-Limit-1 / link-local-source rules are enforced at
        the RX listener handler; the message-class sanity is a no-op
        stub here, mirroring the MLDv2 Query.
        """

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv1 Query message before
        parsing it — the fixed 24-octet form must fit the declared
        IPv6 payload length.
        """

        if not (ICMP6__MLD1__MESSAGE__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__MLD1__MESSAGE__LEN <= ip6__dlen <= len(frame)' is not met. "
                f"Got: {ICMP6__MLD1__MESSAGE__LEN=}, {ip6__dlen=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 MLDv1 Query message from buffer.
        """

        type_, code, cksum, mrd, _reserved, multicast_address_bytes = struct.unpack(
            ICMP6__MLD1__MESSAGE__STRUCT, buffer[:ICMP6__MLD1__MESSAGE__LEN]
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.MULTICAST_LISTENER_QUERY
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6Mld1QueryCode.from_int(code),
            cksum=cksum,
            maximum_response_delay=mrd,
            multicast_address=Ip6Address(bytes(multicast_address_bytes)),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 MLDv1 Query message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(bytearray())
