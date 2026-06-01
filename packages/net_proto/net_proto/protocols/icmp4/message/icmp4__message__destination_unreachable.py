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
This module contains the ICMPv4 Destination Unreachable message support class.

net_proto/protocols/icmp4/message/icmp4__message__destination_unreachable.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
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

# The ICMPv4 Destination Unreachable message (3/[0-3, 5-15]) [RFC 792].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# The ICMPv4 Destination Unreachable message (3/4)
# (Fragmentation Needed and DF Set) [RFC 1191].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP4__DESTINATION_UNREACHABLE__LEN = 8
ICMP4__DESTINATION_UNREACHABLE__STRUCT = "! BBH L"
ICMP4__DESTINATION_UNREACHABLE__FRAGMENTATION_NEEDED__STRUCT = "! BBH HH"


class Icmp4DestinationUnreachableCode(Icmp4Code):
    """
    The ICMPv4 Destination Unreachable 'code' field values.
    """

    NETWORK = 0  # RFC 792: net unreachable.
    HOST = 1  # RFC 792: host unreachable.
    PROTOCOL = 2  # RFC 792: protocol unreachable.
    PORT = 3  # RFC 792: port unreachable.
    FRAGMENTATION_NEEDED = 4  # RFC 792 / RFC 1191 §3: fragmentation needed and DF set (PMTUD).
    SOURCE_ROUTE_FAILED = 5  # RFC 792: source route failed.
    NETWORK_UNKNOWN = 6  # RFC 1122 §3.2.2.1: destination network unknown.
    HOST_UNKNOWN = 7  # RFC 1122 §3.2.2.1: destination host unknown.
    SOURCE_HOST_ISOLATED = 8  # RFC 1122 §3.2.2.1: source host isolated (obsolete).
    NETWORK_PROHIBITED = 9  # RFC 1122 §3.2.2.1: destination network administratively prohibited.
    HOST_PROHIBITED = 10  # RFC 1122 §3.2.2.1: destination host administratively prohibited.
    NETWORK_TOS = 11  # RFC 1122 §3.2.2.1: destination network unreachable for ToS.
    HOST_TOS = 12  # RFC 1122 §3.2.2.1: destination host unreachable for ToS.
    COMMUNICATION_PROHIBITED = 13  # RFC 1812 §5.2.7.1: communication administratively prohibited (firewall).
    HOST_PRECEDENCE = 14  # RFC 1812 §5.2.7.1: host precedence violation.
    PRECEDENCE_CUTOFF = 15  # RFC 1812 §5.2.7.1: precedence cutoff in effect.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Icmp4DestinationUnreachableCode.NETWORK_TOS:
                return "Network TOS"
            case Icmp4DestinationUnreachableCode.HOST_TOS:
                return "Host TOS"
            case _:
                return super().__str__()


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp4MessageDestinationUnreachable(Icmp4Message):
    """
    The ICMPv4 Destination Unreachable message.
    """

    type: Icmp4Type = field(
        repr=False,
        init=False,
        default=Icmp4Type.DESTINATION_UNREACHABLE,
    )
    code: Icmp4DestinationUnreachableCode
    cksum: int = 0

    mtu: int | None = None
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv4 Destination Unreachable message fields.
        """

        assert isinstance(
            self.code, Icmp4DestinationUnreachableCode
        ), f"The 'code' field must be an Icmp4DestinationUnreachableCode. Got: {type(self.code)!r}"

        if self.code == Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
            assert self.mtu is not None and is_uint16(
                self.mtu
            ), f"The 'mtu' field must be a 16-bit unsigned integer. Got: {self.mtu}"

        if self.code != Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
            assert self.mtu is None, f"The 'mtu' field must not be set. Got: {self.mtu}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(self.data)!r}."

        assert len(self.data) <= IP4__PAYLOAD__MAX_LEN - ICMP4__DESTINATION_UNREACHABLE__LEN, (
            f"The 'data' field length must be a 16-bit unsigned integer less than or "
            f"equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__DESTINATION_UNREACHABLE__LEN}. "
            f"Got: {len(self.data)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "data",
            self.data[: IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__DESTINATION_UNREACHABLE__LEN],
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 Destination Unreachable message length.
        """

        return ICMP4__DESTINATION_UNREACHABLE__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 Destination Unreachable message log string.
        """

        mtu_part = f"mtu {self.mtu}, " if self.code == Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED else ""

        return (
            f"ICMPv4 Destination Unreachable - {self.code}, {mtu_part}"
            f"len {len(self)} ({ICMP4__DESTINATION_UNREACHABLE__LEN}+{len(self.data)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv4 Destination Unreachable message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP4__DESTINATION_UNREACHABLE__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP4__DESTINATION_UNREACHABLE__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv4 Destination Unreachable message as bytes.
        """

        match self.code:
            case Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
                struct.pack_into(
                    ICMP4__DESTINATION_UNREACHABLE__FRAGMENTATION_NEEDED__STRUCT,
                    buffer := bytearray(buffer_len),
                    0,
                    int(self.type),
                    int(self.code),
                    0,
                    0,
                    self.mtu,
                )
            case _:
                struct.pack_into(
                    ICMP4__DESTINATION_UNREACHABLE__STRUCT,
                    buffer := bytearray(buffer_len),
                    0,
                    int(self.type),
                    int(self.code),
                    0,
                    0,
                )

        return buffer

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv4 Destination Unreachable message after parsing it.
        """

        # RFC 792 §"Destination Unreachable" defines codes 0..5; RFC 1122 §3.2.2.1
        # adds codes 6..12; RFC 1812 §5.2.7.1 adds codes 13..15. Any value
        # outside that 0..15 range is unassigned by IANA and must be rejected.
        if self.code.is_unknown:
            raise Icmp4SanityError(
                f"The 'code' field of the ICMPv4 Destination Unreachable "
                f"message must be one of {Icmp4DestinationUnreachableCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the ICMPv4 Destination Unreachable message before parsing it.
        """

        if not (ICMP4__DESTINATION_UNREACHABLE__LEN <= ip4__payload_len <= len(frame)):
            raise Icmp4IntegrityError(
                "The condition 'ICMP4__DESTINATION_UNREACHABLE__LEN <= "
                "ip4__payload_len <= len(frame)' must be met. Got: "
                f"{ICMP4__DESTINATION_UNREACHABLE__LEN=}, "
                f"{ip4__payload_len=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv4 Destination Unreachable message from buffer.
        """

        match Icmp4DestinationUnreachableCode.from_int(buffer[1]):
            case Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
                type_, code, cksum, _, mtu = struct.unpack(
                    ICMP4__DESTINATION_UNREACHABLE__FRAGMENTATION_NEEDED__STRUCT,
                    buffer[:ICMP4__DESTINATION_UNREACHABLE__LEN],
                )
            case _:
                type_, code, cksum, _ = struct.unpack(
                    ICMP4__DESTINATION_UNREACHABLE__STRUCT,
                    buffer[:ICMP4__DESTINATION_UNREACHABLE__LEN],
                )
                mtu = None

        assert (received_type := Icmp4Type.from_int(type_)) == (
            valid_type := Icmp4Type.DESTINATION_UNREACHABLE
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp4DestinationUnreachableCode.from_int(code),
            cksum=cksum,
            mtu=mtu,
            data=buffer[ICMP4__DESTINATION_UNREACHABLE__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv4 Destination Unreachable message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
