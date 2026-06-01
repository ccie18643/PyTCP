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
This module contains the IGMP Membership Query message support class —
RX-only at Phase 1 (PyTCP is a host listener, not a querier; the
querier role is Phase-2 router work).

net_proto/protocols/igmp/message/igmp__message__query.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import IP4__ADDRESS_LEN, Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.igmp.igmp__errors import IgmpIntegrityError
from net_proto.protocols.igmp.message.igmp__message import (
    IgmpMessage,
    IgmpType,
    IgmpVersion,
)

# The IGMP Membership Query message [RFC 3376 §4.1 / RFC 2236 §2].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Type = 0x11  | Max Resp Code |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Group Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |   <-- IGMPv3 only
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address [1]                      |   <-- IGMPv3 only
# +-                              .                              -+
# |                       Source Address [N]                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# An IGMPv1/v2 Query is exactly the first 8 octets (Number of Sources
# and the IGMPv3 tail absent); an IGMPv3 Query is at least 12 octets
# (RFC 3376 §7.1 version discrimination).

IGMP__QUERY__SIMPLE__LEN = 8
IGMP__QUERY__SIMPLE__STRUCT = "! BBH 4s"

IGMP__QUERY__V3_MIN_LEN = 12
IGMP__QUERY__V3_FIXED__STRUCT = "! BBH"

# RFC 3376 §4.1.1 — a Max Resp Code (or §4.1.7 QQIC) >= 128 encodes a
# floating-point value as |1| exp(3) | mant(4) |.
IGMP__CODE__FLOAT_THRESHOLD = 128


def decode_igmp_float_code(code: int, /) -> int:
    """
    Decode an IGMP Max Resp Code / QQIC octet to its linear value.

    RFC 3376 §4.1.1 / §4.1.7: a code below 128 is the value itself; a
    code of 128 or more is a floating-point form 1|exp|mant decoding to
    (mant | 0x10) << (exp + 3).
    """

    if code < IGMP__CODE__FLOAT_THRESHOLD:
        return code

    exp = (code >> 4) & 0x07
    mant = code & 0x0F

    return (mant | 0x10) << (exp + 3)


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpMessageQuery(IgmpMessage):
    """
    The IGMP Membership Query message — RX-only at Phase 1. PyTCP is a
    host listener; this message class parses inbound Queries for the
    host Report-on-Query state machine. Phase-2 router work will add
    full querier-side construction + emission via 'assemble'.
    """

    type: IgmpType = field(
        repr=False,
        init=False,
        default=IgmpType.MEMBERSHIP_QUERY,
    )
    cksum: int = 0

    version: IgmpVersion = IgmpVersion.V3
    max_resp_code: int = 0
    group_address: Ip4Address = Ip4Address()
    s_flag: bool = False
    qrv: int = 0
    qqic: int = 0
    source_addresses: tuple[Ip4Address, ...] = ()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IGMP Membership Query message fields.
        """

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert (
            0 <= self.max_resp_code <= 0xFF
        ), f"The 'max_resp_code' field must be an 8-bit unsigned integer. Got: {self.max_resp_code!r}"

        assert 0 <= self.qqic <= 0xFF, f"The 'qqic' field must be an 8-bit unsigned integer. Got: {self.qqic!r}"

        assert 0 <= self.qrv <= 0x07, f"The 'qrv' field must be a 3-bit unsigned integer. Got: {self.qrv!r}"

    @property
    def max_response_time(self) -> int:
        """
        Get the IGMP Query 'max_response_time' field in units of 1/10 s.
        """

        return decode_igmp_float_code(self.max_resp_code)

    @property
    def querier_query_interval(self) -> int:
        """
        Get the IGMP Query 'querier_query_interval' field in seconds.
        """

        return decode_igmp_float_code(self.qqic)

    @property
    def number_of_sources(self) -> int:
        """
        Get the IGMP Query 'number_of_sources' field.
        """

        return len(self.source_addresses)

    @property
    def is_general_query(self) -> bool:
        """
        Get whether this is a General Query (group 0.0.0.0, no sources).
        """

        return self.group_address.is_unspecified and not self.source_addresses

    @override
    def __len__(self) -> int:
        """
        Get the IGMP Membership Query message length.
        """

        if self.version is IgmpVersion.V3:
            return IGMP__QUERY__V3_MIN_LEN + IP4__ADDRESS_LEN * self.number_of_sources

        return IGMP__QUERY__SIMPLE__LEN

    @override
    def __str__(self) -> str:
        """
        Get the IGMP Membership Query message log string.
        """

        return (
            f"IGMP Query v{int(self.version)}, group {self.group_address}, "
            f"max_resp_time {self.max_response_time}, "
            f"qrv {self.qrv}, qqic {self.qqic}, sources {self.number_of_sources}"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IGMP Membership Query message as a memoryview. The
        Phase-1 host listener only consumes Queries; an empty
        memoryview is returned rather than raising so a caller that
        round-trips through an assembler does not crash (the canonical
        use is RX-only).
        """

        return memoryview(b"")

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the IGMP Membership Query message after parsing
        it. The Hop-Limit (TTL=1) / Router-Alert / source checks are
        enforced at the RX handler, which has the IPv4 header context;
        the message-class sanity is a no-op stub here.
        """

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the IGMP Membership Query message before
        parsing it.
        """

        if ip4__payload_len < IGMP__QUERY__SIMPLE__LEN:
            raise IgmpIntegrityError(
                "The condition 'IGMP__QUERY__SIMPLE__LEN <= ip4__payload_len' is not met. "
                f"Got: {IGMP__QUERY__SIMPLE__LEN=}, {ip4__payload_len=}"
            )

        # RFC 3376 §7.1 — a Query of 8 octets is IGMPv1/v2; a Query of
        # 12+ octets is IGMPv3. Lengths 9-11 are ambiguous and ignored.
        if IGMP__QUERY__SIMPLE__LEN < ip4__payload_len < IGMP__QUERY__V3_MIN_LEN:
            raise IgmpIntegrityError(
                "An IGMP Query of 9-11 octets is ambiguous and ignored (RFC 3376 §7.1). " f"Got: {ip4__payload_len=}"
            )

        if ip4__payload_len >= IGMP__QUERY__V3_MIN_LEN:
            number_of_sources = int.from_bytes(frame[10:12], "big")
            expected_len = IGMP__QUERY__V3_MIN_LEN + IP4__ADDRESS_LEN * number_of_sources

            # RFC 3376 §4.1.10 permits trailing additional data beyond
            # the source list, so the declared list must fit but need
            # not consume the whole payload.
            if expected_len > ip4__payload_len:
                raise IgmpIntegrityError(
                    "The IGMPv3 Query payload truncates the declared source-address list. "
                    f"Got: {number_of_sources=}, {expected_len=}, {ip4__payload_len=}"
                )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IGMP Membership Query message from buffer. The
        buffer is the IGMP message sliced to its declared length, so
        'len(buffer)' carries the RFC 3376 §7.1 version discrimination.
        """

        type_, max_resp_code, cksum, group_bytes = struct.unpack(
            IGMP__QUERY__SIMPLE__STRUCT, buffer[:IGMP__QUERY__SIMPLE__LEN]
        )

        assert (received_type := IgmpType.from_int(type_)) == (
            valid_type := IgmpType.MEMBERSHIP_QUERY
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        group_address = Ip4Address(bytes(group_bytes))

        if len(buffer) >= IGMP__QUERY__V3_MIN_LEN:
            resv_s_qrv, qqic, number_of_sources = struct.unpack(
                IGMP__QUERY__V3_FIXED__STRUCT, buffer[IGMP__QUERY__SIMPLE__LEN:IGMP__QUERY__V3_MIN_LEN]
            )
            s_flag = bool(resv_s_qrv & 0x08)
            qrv = resv_s_qrv & 0x07
            source_bytes = buffer[
                IGMP__QUERY__V3_MIN_LEN : IGMP__QUERY__V3_MIN_LEN + IP4__ADDRESS_LEN * number_of_sources
            ]
            source_addresses = tuple(
                Ip4Address(bytes(source_bytes[i : i + IP4__ADDRESS_LEN]))
                for i in range(0, len(source_bytes), IP4__ADDRESS_LEN)
            )

            return cls(
                version=IgmpVersion.V3,
                cksum=cksum,
                max_resp_code=max_resp_code,
                group_address=group_address,
                s_flag=s_flag,
                qrv=qrv,
                qqic=qqic,
                source_addresses=source_addresses,
            )

        return cls(
            version=IgmpVersion.V1 if max_resp_code == 0 else IgmpVersion.V2,
            cksum=cksum,
            max_resp_code=max_resp_code,
            group_address=group_address,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IGMP Membership Query message into the buffer list.
        The Phase-1 host listener does not emit Queries; raises
        NotImplementedError if called.
        """

        raise NotImplementedError("IGMP Query assembly is Phase-2 router work; PyTCP is a host listener.")
