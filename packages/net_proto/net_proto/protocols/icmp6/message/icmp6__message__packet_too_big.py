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
This module contains the ICMPv6 Packet Too Big message support class
(RFC 4443 §3.2 / RFC 8201 §4 — IPv6 PMTUD signalling).

net_proto/protocols/icmp6/message/icmp6__message__packet_too_big.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip6Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError, Icmp6SanityError
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.ip6.ip6__header import (
    IP6__HEADER__LEN,
    IP6__MIN_MTU,
    IP6__PAYLOAD__MAX_LEN,
)

# The ICMPv6 Packet Too Big message (2/0) [RFC 4443 §3.2].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                              MTU                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                  As much of the invoking packet               ~
# ~      as possible without the ICMPv6 packet exceeding 1280     ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__PACKET_TOO_BIG__LEN = 8
ICMP6__PACKET_TOO_BIG__STRUCT = "! BBH L"


class Icmp6PacketTooBigCode(Icmp6Code):
    """
    The ICMPv6 Packet Too Big 'code' field values. RFC 4443 §3.2
    defines a single code (0).
    """

    DEFAULT = 0  # RFC 4443 §3.2: only code 0 defined.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6MessagePacketTooBig(Icmp6Message):
    """
    The ICMPv6 Packet Too Big message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.PACKET_TOO_BIG,
    )
    code: Icmp6PacketTooBigCode = Icmp6PacketTooBigCode.DEFAULT
    cksum: int = 0

    mtu: int = 0
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 Packet Too Big message fields.
        """

        assert isinstance(
            self.code, Icmp6PacketTooBigCode
        ), f"The 'code' field must be an Icmp6PacketTooBigCode. Got: {type(self.code)!r}"

        assert is_uint32(self.mtu), f"The 'mtu' field must be a 32-bit unsigned integer. Got: {self.mtu!r}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(self.data)!r}"

        assert len(self.data) <= IP6__PAYLOAD__MAX_LEN - ICMP6__PACKET_TOO_BIG__LEN, (
            f"The 'data' field length must be a 16-bit unsigned integer less than "
            f"or equal to {IP6__PAYLOAD__MAX_LEN - ICMP6__PACKET_TOO_BIG__LEN}. "
            f"Got: {len(self.data)!r}"
        )

        # RFC 4443 §3.2: total ICMPv6 packet size MUST NOT exceed
        # IPv6 minimum MTU. Truncate the embedded data accordingly.
        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "data",
            self.data[: IP6__MIN_MTU - IP6__HEADER__LEN - ICMP6__PACKET_TOO_BIG__LEN],
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 Packet Too Big message length.
        """

        return ICMP6__PACKET_TOO_BIG__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 Packet Too Big message log string.
        """

        return (
            f"ICMPv6 Packet Too Big - mtu {self.mtu}, len {len(self)} "
            f"({ICMP6__PACKET_TOO_BIG__LEN}+{len(self.data)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 Packet Too Big message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP6__PACKET_TOO_BIG__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__PACKET_TOO_BIG__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 Packet Too Big message header as bytes.
        """

        struct.pack_into(
            ICMP6__PACKET_TOO_BIG__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            self.mtu,
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 Packet Too Big message after parsing it.
        """

        # RFC 4443 §3.2 defines a single code value (0). Any other value is
        # unassigned by IANA and must be rejected.
        if self.code.is_unknown:
            raise Icmp6SanityError(
                f"The 'code' field of the ICMPv6 Packet Too Big message "
                f"must be one of {Icmp6PacketTooBigCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 Packet Too Big message before parsing it.
        """

        if not (ICMP6__PACKET_TOO_BIG__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__PACKET_TOO_BIG__LEN <= "
                "ip6__dlen <= len(frame)' must be met. Got: "
                f"{ICMP6__PACKET_TOO_BIG__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 Packet Too Big message from buffer.
        """

        type_, code, cksum, mtu = struct.unpack(
            ICMP6__PACKET_TOO_BIG__STRUCT,
            buffer[:ICMP6__PACKET_TOO_BIG__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.PACKET_TOO_BIG
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6PacketTooBigCode.from_int(code),
            cksum=cksum,
            mtu=mtu,
            data=buffer[ICMP6__PACKET_TOO_BIG__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 Packet Too Big message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
