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
This module contains the ICMPv6 Time Exceeded message support class.

net_proto/protocols/icmp6/message/icmp6__message__time_exceeded.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
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

# The ICMPv6 Time Exceeded message (3/[0-1]) [RFC 4443 §3.3].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            unused                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                As much of invoking packet as fits in MIN_MTU  ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__TIME_EXCEEDED__LEN = 8
ICMP6__TIME_EXCEEDED__STRUCT = "! BBH L"


class Icmp6TimeExceededCode(Icmp6Code):
    """
    The ICMPv6 Time Exceeded 'code' field values (RFC 4443 §3.3).
    """

    HOP_LIMIT_EXCEEDED_IN_TRANSIT = 0  # RFC 4443 §3.3: hop limit reached zero in transit.
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1  # RFC 4443 §3.3 / RFC 8200 §4.5: fragment reassembly timer expired.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6MessageTimeExceeded(Icmp6Message):
    """
    The ICMPv6 Time Exceeded message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.TIME_EXCEEDED,
    )
    code: Icmp6TimeExceededCode
    cksum: int = 0

    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 Time Exceeded message fields.
        """

        assert isinstance(
            self.code, Icmp6TimeExceededCode
        ), f"The 'code' field must be an Icmp6TimeExceededCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(self.data)!r}"

        assert len(self.data) <= IP6__PAYLOAD__MAX_LEN - ICMP6__TIME_EXCEEDED__LEN, (
            f"The 'data' field length must be a 16-bit unsigned integer less than "
            f"or equal to {IP6__PAYLOAD__MAX_LEN - ICMP6__TIME_EXCEEDED__LEN}. "
            f"Got: {len(self.data)!r}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "data",
            self.data[: IP6__MIN_MTU - IP6__HEADER__LEN - ICMP6__TIME_EXCEEDED__LEN],
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 Time Exceeded message length.
        """

        return ICMP6__TIME_EXCEEDED__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 Time Exceeded message log string.
        """

        return f"ICMPv6 Time Exceeded - {self.code}, len {len(self)} " f"({ICMP6__TIME_EXCEEDED__LEN}+{len(self.data)})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 Time Exceeded message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP6__TIME_EXCEEDED__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__TIME_EXCEEDED__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 Time Exceeded message as bytes.
        """

        struct.pack_into(
            ICMP6__TIME_EXCEEDED__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            0,
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 Time Exceeded message after parsing it.
        """

        # RFC 4443 §3.3 defines codes 0..1 (Hop Limit exceeded in transit /
        # Fragment reassembly time exceeded). Any other value is unassigned.
        if self.code.is_unknown:
            raise Icmp6SanityError(
                f"The 'code' field of the ICMPv6 Time Exceeded message "
                f"must be one of {Icmp6TimeExceededCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 Time Exceeded message before parsing it.
        """

        if not (ICMP6__TIME_EXCEEDED__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__TIME_EXCEEDED__LEN <= ip6__dlen <= "
                f"len(frame)' must be met. Got: {ICMP6__TIME_EXCEEDED__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 Time Exceeded message from buffer.
        """

        type_, code, cksum, _ = struct.unpack(
            ICMP6__TIME_EXCEEDED__STRUCT,
            buffer[:ICMP6__TIME_EXCEEDED__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.TIME_EXCEEDED
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6TimeExceededCode.from_int(code),
            cksum=cksum,
            data=buffer[ICMP6__TIME_EXCEEDED__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 Time Exceeded message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
