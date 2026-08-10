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
This module contains the ICMPv6 MLDv2 Query message support class. The
parser feeds the §5.1.10 host Report-on-Query handler; the assembler
is the querier-side emission path (Phase-2 router work).

net_proto/protocols/icmp6/message/mld2/icmp6__mld2__message__query.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp6.icmp6__errors import (
    Icmp6IntegrityError,
)
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)

# The ICMPv6 MLDv2 Query message (130/0) [RFC 3810 §5.1].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Maximum Response Code      |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# *                                                               *
# |                                                               |
# *                       Multicast Address                       *
# |                                                               |
# *                                                               *
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Source Address [1..N]                        ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__MLD2__QUERY__LEN = 28
ICMP6__MLD2__QUERY__STRUCT = "! BBH HH 16s BBH"


class Icmp6Mld2QueryCode(Icmp6Code):
    """
    The ICMPv6 MLDv2 Query 'code' field values.
    """

    DEFAULT = 0  # RFC 3810 §5.1: only code 0 defined.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6Mld2MessageQuery(Icmp6Message):
    """
    The ICMPv6 MLDv2 Query message. On RX the parser feeds the
    §5.1.10 host Report-on-Query handler; on TX the Phase-2 querier
    assembles it to emit General / Multicast-Address-Specific /
    Multicast-Address-and-Source-Specific Queries.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.MULTICAST_LISTENER_QUERY,
    )
    code: Icmp6Mld2QueryCode = Icmp6Mld2QueryCode.DEFAULT
    cksum: int = 0

    maximum_response_code: int = 0
    multicast_address: Ip6Address = Ip6Address()
    s_flag: bool = False
    qrv: int = 0
    qqic: int = 0
    source_addresses: tuple[Ip6Address, ...] = ()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv2 Query message fields.
        """

        assert isinstance(
            self.code, Icmp6Mld2QueryCode
        ), f"The 'code' field must be an Icmp6Mld2QueryCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert is_uint16(
            self.maximum_response_code
        ), f"The 'maximum_response_code' field must be uint16. Got: {self.maximum_response_code!r}"

        assert isinstance(
            self.multicast_address, Ip6Address
        ), f"The 'multicast_address' field must be an Ip6Address. Got: {type(self.multicast_address)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 MLDv2 Query message length.
        """

        return ICMP6__MLD2__QUERY__LEN + 16 * len(self.source_addresses)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 MLDv2 Query message log string.
        """

        return (
            f"ICMPv6 MLDv2 Query, mrc={self.maximum_response_code}, "
            f"multicast={self.multicast_address}, "
            f"qrv={self.qrv}, qqic={self.qqic}, "
            f"sources={len(self.source_addresses)}"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 MLDv2 Query message as a memoryview, with the
        checksum slot left zero for the ICMPv6 base to inject.
        """

        buffer = self._pack_header()
        buffer[ICMP6__MLD2__QUERY__LEN:] = self._pack_sources()

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__MLD2__QUERY__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 MLDv2 Query fixed 28-octet header as bytes.
        """

        struct.pack_into(
            ICMP6__MLD2__QUERY__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            self.maximum_response_code,
            0,
            bytes(self.multicast_address),
            (self.s_flag << 3) | self.qrv,
            self.qqic,
            len(self.source_addresses),
        )

        return buffer

    def _pack_sources(self) -> bytearray:
        """
        Get the ICMPv6 MLDv2 Query source-address list as bytes.
        """

        buffer = bytearray()

        for source in self.source_addresses:
            buffer += bytes(source)

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 MLDv2 Query message after parsing it.

        RFC 3810 §5.1.13 — MLDv2 Queries MUST be received with
        Hop Limit = 1; otherwise they are silently ignored.
        The listener also rejects Queries from a non-link-local
        source per §5.1.14.
        """

        # The Hop Limit / source-link-local sanity rules are
        # enforced at the RX path (the listener handler can
        # apply Linux-faithful "tolerate non-link-local from
        # SEND-style routers" via sysctl in the future); the
        # message-class sanity is a no-op stub here.

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv2 Query message
        before parsing it. Validates the fixed 28-byte
        header plus N × 16-byte source-address list.
        """

        if not (ICMP6__MLD2__QUERY__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__MLD2__QUERY__LEN <= ip6__dlen <= len(frame)' is not met. "
                f"Got: {ICMP6__MLD2__QUERY__LEN=}, {ip6__dlen=}, {len(frame)=}"
            )

        # Number of Sources at offset 26-27.
        number_of_sources = int.from_bytes(frame[26:28], "big")
        expected_len = ICMP6__MLD2__QUERY__LEN + 16 * number_of_sources

        if ip6__dlen < expected_len:
            raise Icmp6IntegrityError(
                "The MLDv2 Query payload truncates the declared source-address list. "
                f"Got: {number_of_sources=}, {expected_len=}, {ip6__dlen=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 MLDv2 Query message from buffer.
        """

        (
            type_,
            code,
            cksum,
            mrc,
            _reserved,
            multicast_address_bytes,
            resv_s_qrv,
            qqic,
            number_of_sources,
        ) = struct.unpack(ICMP6__MLD2__QUERY__STRUCT, buffer[:ICMP6__MLD2__QUERY__LEN])

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.MULTICAST_LISTENER_QUERY
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        s_flag = bool(resv_s_qrv & 0x08)
        qrv = resv_s_qrv & 0x07

        source_bytes = buffer[ICMP6__MLD2__QUERY__LEN : ICMP6__MLD2__QUERY__LEN + 16 * number_of_sources]
        source_addresses = tuple(Ip6Address(bytes(source_bytes[i : i + 16])) for i in range(0, len(source_bytes), 16))

        return cls(
            code=Icmp6Mld2QueryCode.from_int(code),
            cksum=cksum,
            maximum_response_code=mrc,
            multicast_address=Ip6Address(bytes(multicast_address_bytes)),
            s_flag=s_flag,
            qrv=qrv,
            qqic=qqic,
            source_addresses=source_addresses,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 MLDv2 Query message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self._pack_sources())
