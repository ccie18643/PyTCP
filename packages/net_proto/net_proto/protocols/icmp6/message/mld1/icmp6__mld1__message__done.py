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
This module contains the ICMPv6 MLDv1 Multicast Listener Done
message (type 132) support class. A host emits this when it leaves
a multicast group while its interface is in MLDv1 compatibility
mode (RFC 3810 §8.3.1), the MLDv1 analogue of the MLDv2
BLOCK_OLD_SOURCES / "leaving the group" state-change record.

net_proto/protocols/icmp6/message/mld1/icmp6__mld1__message__done.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp6.icmp6__errors import (
    Icmp6IntegrityError,
    Icmp6SanityError,
)
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    ICMP6__MLD1__MESSAGE__LEN,
    ICMP6__MLD1__MESSAGE__STRUCT,
)

# The ICMPv6 MLDv1 Multicast Listener Done message (132/0) [RFC 2710 §3].
# Shares the fixed 24-octet MLDv1 message layout (the field constants
# live in the Report module). Maximum Response Delay is set to zero by
# the sender and ignored by receivers in a Done message.
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


class Icmp6Mld1DoneCode(Icmp6Code):
    """
    The ICMPv6 MLDv1 Done 'code' field values.
    """

    DEFAULT = 0  # RFC 2710 §3: the Code field is set to zero.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6Mld1MessageDone(Icmp6Message):
    """
    The ICMPv6 MLDv1 Multicast Listener Done message. Shares the
    fixed 24-octet RFC 2710 §3 wire form with the MLDv1 Report,
    differing only in the type byte (132 vs 131) and the
    destination the RX/TX path uses (Done is sent to the
    all-routers address ff02::2).
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.MULTICAST_LISTENER_DONE,
    )
    code: Icmp6Mld1DoneCode = Icmp6Mld1DoneCode.DEFAULT
    cksum: int = 0

    multicast_address: Ip6Address = Ip6Address()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv1 Done message fields.
        """

        assert isinstance(
            self.code, Icmp6Mld1DoneCode
        ), f"The 'code' field must be an Icmp6Mld1DoneCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert isinstance(
            self.multicast_address, Ip6Address
        ), f"The 'multicast_address' field must be an Ip6Address. Got: {type(self.multicast_address)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 MLDv1 Done message length.
        """

        return ICMP6__MLD1__MESSAGE__LEN

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 MLDv1 Done message log string.
        """

        return f"ICMPv6 MLDv1 Done, multicast {self.multicast_address}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 MLDv1 Done message as a memoryview.
        """

        return memoryview(self._pack_header())

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__MLD1__MESSAGE__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 MLDv1 Done message header as bytes. The
        checksum is left zero; the ICMPv6 packet assembler injects
        the one's-complement checksum over the pseudo-header.
        """

        struct.pack_into(
            ICMP6__MLD1__MESSAGE__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            0,
            0,
            bytes(self.multicast_address),
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 MLDv1 Done message after parsing
        it. RFC 2710 §3 / §4 — MLD messages travel with Hop Limit 1.
        """

        if ip6__hop != 1:
            raise Icmp6SanityError(
                f"MLDv1 Done - [RFC 2710] The 'ip6__hop' field must be 1. Got: {ip6__hop!r}",
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv1 Done message before
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
        Initialize the ICMPv6 MLDv1 Done message from buffer.
        """

        type_, code, cksum, _mrd, _reserved, multicast_address_bytes = struct.unpack(
            ICMP6__MLD1__MESSAGE__STRUCT, buffer[:ICMP6__MLD1__MESSAGE__LEN]
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.MULTICAST_LISTENER_DONE
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6Mld1DoneCode.from_int(code),
            cksum=cksum,
            multicast_address=Ip6Address(bytes(multicast_address_bytes)),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 MLDv1 Done message into the buffer list.

        Appends the 24-octet message plus an empty trailing buffer so
        the enclosing 'Icmp6Assembler' can inject the checksum over the
        last two buffers.
        """

        buffers.append(self._pack_header())
        buffers.append(bytearray())
