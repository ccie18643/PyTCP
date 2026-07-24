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
This module contains the ICMPv4 Redirect message support class.

net_proto/protocols/icmp4/message/icmp4__message__redirect.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip4Address
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

# The ICMPv4 Redirect message (5/[0-3]) [RFC 792].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                 Gateway Internet Address                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP4__REDIRECT__LEN = 8
ICMP4__REDIRECT__STRUCT = "! BBH 4s"


class Icmp4RedirectCode(Icmp4Code):
    """
    The ICMPv4 Redirect 'code' field values.
    """

    NETWORK = 0  # RFC 792: redirect datagrams for the Network.
    HOST = 1  # RFC 792: redirect datagrams for the Host.
    TOS_NETWORK = 2  # RFC 792: redirect datagrams for the Type of Service and Network.
    TOS_HOST = 3  # RFC 792: redirect datagrams for the Type of Service and Host.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp4MessageRedirect(Icmp4Message):
    """
    The ICMPv4 Redirect message.
    """

    type: Icmp4Type = field(
        repr=False,
        init=False,
        default=Icmp4Type.REDIRECT,
    )
    code: Icmp4RedirectCode
    cksum: int = 0

    gateway: Ip4Address
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv4 Redirect message fields.
        """

        assert isinstance(
            self.code, Icmp4RedirectCode
        ), f"The 'code' field must be an Icmp4RedirectCode. Got: {type(self.code)!r}"

        assert isinstance(
            self.gateway, Ip4Address
        ), f"The 'gateway' field must be an Ip4Address. Got: {type(self.gateway)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(self.data)!r}."

        assert len(self.data) <= IP4__PAYLOAD__MAX_LEN - ICMP4__REDIRECT__LEN, (
            f"The 'data' field length must be a 16-bit unsigned integer less than or "
            f"equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__REDIRECT__LEN}. "
            f"Got: {len(self.data)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "data",
            self.data[: IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__REDIRECT__LEN],
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 Redirect message length.
        """

        return ICMP4__REDIRECT__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 Redirect message log string.
        """

        return (
            f"ICMPv4 Redirect - {self.code}, gateway {self.gateway}, "
            f"len {len(self)} ({ICMP4__REDIRECT__LEN}+{len(self.data)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv4 Redirect message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP4__REDIRECT__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP4__REDIRECT__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv4 Redirect message header as bytes.
        """

        struct.pack_into(
            ICMP4__REDIRECT__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            bytes(self.gateway),
        )

        return buffer

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv4 Redirect message after parsing it.
        """

        # RFC 792 §"Redirect Message" defines codes 0..3; any value
        # outside that range is unassigned by IANA and must be rejected.
        if self.code.is_unknown:
            raise Icmp4SanityError(
                f"The 'code' field of the ICMPv4 Redirect message must be one of "
                f"{Icmp4RedirectCode.get_known_values()}. Got: {int(self.code)}."
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the ICMPv4 Redirect message before parsing it.
        """

        if not (ICMP4__REDIRECT__LEN <= ip4__payload_len <= len(frame)):
            raise Icmp4IntegrityError(
                "The condition 'ICMP4__REDIRECT__LEN <= ip4__payload_len <= "
                f"len(frame)' must be met. Got: {ICMP4__REDIRECT__LEN=}, "
                f"{ip4__payload_len=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv4 Redirect message from buffer.
        """

        type_, code, cksum, gateway = struct.unpack(
            ICMP4__REDIRECT__STRUCT,
            buffer[:ICMP4__REDIRECT__LEN],
        )

        assert (received_type := Icmp4Type.from_int(type_)) == (
            valid_type := Icmp4Type.REDIRECT
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp4RedirectCode.from_int(code),
            cksum=cksum,
            gateway=Ip4Address(gateway),
            data=buffer[ICMP4__REDIRECT__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv4 Redirect message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
