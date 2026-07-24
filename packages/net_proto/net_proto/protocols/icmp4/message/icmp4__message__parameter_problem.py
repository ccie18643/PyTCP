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
This module contains the ICMPv4 Parameter Problem message support class.

net_proto/protocols/icmp4/message/icmp4__message__parameter_problem.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8, is_uint16
from net_proto.protocols.icmp4.icmp4__errors import Icmp4IntegrityError, Icmp4SanityError
from net_proto.protocols.icmp4.message.icmp4__message import (
    Icmp4Code,
    Icmp4Message,
    Icmp4Type,
)
from net_proto.protocols.ip4.ip4__header import (
    IP4__HEADER__LEN,
    IP4__MIN_MTU,
    IP4__PAYLOAD__MAX_LEN,
)

# The ICMPv4 Parameter Problem message (12/[0-2]) [RFC 792, RFC 1122].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Pointer    |                   unused                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP4__PARAMETER_PROBLEM__LEN = 8
ICMP4__PARAMETER_PROBLEM__STRUCT = "! BBH BBH"


class Icmp4ParameterProblemCode(Icmp4Code):
    """
    The ICMPv4 Parameter Problem 'code' field values.
    """

    POINTER_INDICATES_ERROR = 0  # RFC 792
    REQUIRED_OPTION_MISSING = 1  # RFC 1122 §3.2.2.5
    BAD_LENGTH = 2  # RFC 1812 §5.2.7.1

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR:
                return "Pointer Indicates Error"
            case Icmp4ParameterProblemCode.REQUIRED_OPTION_MISSING:
                return "Required Option Missing"
            case Icmp4ParameterProblemCode.BAD_LENGTH:
                return "Bad Length"
            case _:
                return super().__str__()


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp4MessageParameterProblem(Icmp4Message):
    """
    The ICMPv4 Parameter Problem message.
    """

    type: Icmp4Type = field(
        repr=False,
        init=False,
        default=Icmp4Type.PARAMETER_PROBLEM,
    )
    code: Icmp4ParameterProblemCode
    cksum: int = 0

    pointer: int = 0
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv4 Parameter Problem message fields.
        """

        assert isinstance(
            self.code, Icmp4ParameterProblemCode
        ), f"The 'code' field must be an Icmp4ParameterProblemCode. Got: {type(self.code)!r}"

        assert is_uint8(self.pointer), f"The 'pointer' field must be an 8-bit unsigned integer. Got: {self.pointer}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(self.data)!r}."

        assert len(self.data) <= IP4__PAYLOAD__MAX_LEN - ICMP4__PARAMETER_PROBLEM__LEN, (
            f"The 'data' field length must be a 16-bit unsigned integer less than or "
            f"equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__PARAMETER_PROBLEM__LEN}. "
            f"Got: {len(self.data)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "data",
            self.data[: IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__PARAMETER_PROBLEM__LEN],
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 Parameter Problem message length.
        """

        return ICMP4__PARAMETER_PROBLEM__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 Parameter Problem message log string.
        """

        return (
            f"ICMPv4 Parameter Problem - {self.code}, pointer {self.pointer}, "
            f"len {len(self)} ({ICMP4__PARAMETER_PROBLEM__LEN}+{len(self.data)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv4 Parameter Problem message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP4__PARAMETER_PROBLEM__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP4__PARAMETER_PROBLEM__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv4 Parameter Problem message as bytes.
        """

        struct.pack_into(
            ICMP4__PARAMETER_PROBLEM__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            self.pointer,
            0,
            0,
        )

        return buffer

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv4 Parameter Problem message after parsing it.
        """

        # RFC 792 defines code 0 (pointer); RFC 1122 §3.2.2.5 adds codes 1
        # (missing required option) and 2 (bad length). Any other value is
        # unassigned by IANA and must be rejected.
        if self.code.is_unknown:
            raise Icmp4SanityError(
                f"The 'code' field of the ICMPv4 Parameter Problem message "
                f"must be one of {Icmp4ParameterProblemCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the ICMPv4 Parameter Problem message before parsing it.
        """

        if not (ICMP4__PARAMETER_PROBLEM__LEN <= ip4__payload_len <= len(frame)):
            raise Icmp4IntegrityError(
                "The condition 'ICMP4__PARAMETER_PROBLEM__LEN <= ip4__payload_len <= "
                f"len(frame)' must be met. Got: {ICMP4__PARAMETER_PROBLEM__LEN=}, "
                f"{ip4__payload_len=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv4 Parameter Problem message from buffer.
        """

        type_, code, cksum, pointer, _, _ = struct.unpack(
            ICMP4__PARAMETER_PROBLEM__STRUCT,
            buffer[:ICMP4__PARAMETER_PROBLEM__LEN],
        )

        assert (received_type := Icmp4Type.from_int(type_)) == (
            valid_type := Icmp4Type.PARAMETER_PROBLEM
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp4ParameterProblemCode.from_int(code),
            cksum=cksum,
            pointer=pointer,
            data=buffer[ICMP4__PARAMETER_PROBLEM__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv4 Parameter Problem message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
