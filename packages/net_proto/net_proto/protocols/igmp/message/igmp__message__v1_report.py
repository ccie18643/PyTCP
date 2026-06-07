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
This module contains the IGMPv1 Membership Report message support
class — the legacy form a host emits under an IGMPv1 querier.

net_proto/protocols/igmp/message/igmp__message__v1_report.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip4Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.igmp.igmp__errors import (
    IgmpIntegrityError,
    IgmpSanityError,
)
from net_proto.protocols.igmp.message.igmp__message import (
    IgmpMessage,
    IgmpType,
)

# The IGMPv1 Membership Report message (0x12) [RFC 1112 Appendix I].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Type = 0x12   |    Unused     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Group Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# In IGMPv1 the second octet is Unused (set to zero by the sender and
# ignored on receipt).

IGMP__V1_REPORT__LEN = 8
IGMP__V1_REPORT__STRUCT = "! BBH 4s"


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpMessageV1Report(IgmpMessage):
    """
    The IGMPv1 Membership Report message.
    """

    type: IgmpType = field(
        repr=False,
        init=False,
        default=IgmpType.V1_MEMBERSHIP_REPORT,
    )
    cksum: int = 0
    group_address: Ip4Address = Ip4Address()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IGMPv1 Membership Report message fields.
        """

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

    @override
    def __len__(self) -> int:
        """
        Get the IGMPv1 Membership Report message length.
        """

        return IGMP__V1_REPORT__LEN

    @override
    def __str__(self) -> str:
        """
        Get the IGMPv1 Membership Report message log string.
        """

        return f"IGMPv1 Membership Report group {self.group_address}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IGMPv1 Membership Report message as a memoryview, with
        the checksum slot left zero for the IGMP base to inject.
        """

        struct.pack_into(
            IGMP__V1_REPORT__STRUCT,
            buffer := bytearray(IGMP__V1_REPORT__LEN),
            0,
            int(self.type),
            0,
            0,
            bytes(self.group_address),
        )

        return memoryview(buffer)

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the IGMPv1 Membership Report message after
        parsing it.
        """

        # RFC 1112 — the Group Address field holds the IP multicast
        # group being reported, so a non-multicast group is invalid.
        if not self.group_address.is_multicast:
            raise IgmpSanityError(f"The 'group_address' field must be a multicast address. Got: {self.group_address!r}")

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the IGMPv1 Membership Report message before
        parsing it.
        """

        if not (IGMP__V1_REPORT__LEN <= ip4__payload_len <= len(frame)):
            raise IgmpIntegrityError(
                "The condition 'IGMP__V1_REPORT__LEN <= ip4__payload_len <= len(frame)' is not met. "
                f"Got: {IGMP__V1_REPORT__LEN=}, {ip4__payload_len=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IGMPv1 Membership Report message from buffer.
        """

        type_, _, cksum, group_bytes = struct.unpack(IGMP__V1_REPORT__STRUCT, buffer[:IGMP__V1_REPORT__LEN])

        assert (received_type := IgmpType.from_int(type_)) == (
            valid_type := IgmpType.V1_MEMBERSHIP_REPORT
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(cksum=cksum, group_address=Ip4Address(bytes(group_bytes)))

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IGMPv1 Membership Report message into the buffer list.
        """

        buffers.append(bytearray(memoryview(self)))
