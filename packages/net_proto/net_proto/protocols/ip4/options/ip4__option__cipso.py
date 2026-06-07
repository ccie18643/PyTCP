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
This module contains the IPv4 CIPSO (Commercial IP Security Option)
support code (FIPS-188 / Linux NetLabel).

This is a SHALLOW implementation: the option is parsed into its
DOI + opaque tag bytes for wire-level round-trip and Echo Reply
echo. Tag-type-specific decoding (rbitmap / enumerated / ranged
/ permissive / free-form per FIPS-188 §A.4) is NOT implemented
because PyTCP has no NetLabel/SELinux MLS consumer to feed.

net_proto/protocols/ip4/options/ip4__option__cipso.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.options.ip4__option import Ip4Option, Ip4OptionType

# The IPv4 CIPSO option [FIPS-188 / Linux NetLabel].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Type = 134   |    Length     | DOI (high)    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       DOI (continued, 4 bytes total)          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Tag 1   ...                                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Tag N   ...                                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP4__OPTION__CIPSO__HDR_LEN = 2
IP4__OPTION__CIPSO__DOI_LEN = 4
IP4__OPTION__CIPSO__MIN_LEN = IP4__OPTION__CIPSO__HDR_LEN + IP4__OPTION__CIPSO__DOI_LEN
IP4__OPTION__CIPSO__TAG_HDR_LEN = 2
IP4__OPTION__CIPSO__STRUCT = "! BBL"


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4OptionCipso(Ip4Option):
    """
    The IPv4 CIPSO (Commercial IP Security Option) support class.

    Shallow representation: 'tags' is a list of opaque tag bytes,
    each entry containing the full tag (type byte + length byte +
    content). Tag-type-specific decoding is intentionally not
    performed.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.CIPSO,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    doi: int
    tags: list[bytes]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 CIPSO option fields.
        """

        assert is_uint32(self.doi), f"The 'doi' field must be a 32-bit unsigned integer. Got: {self.doi!r}"

        for index, tag in enumerate(self.tags):
            assert len(tag) >= IP4__OPTION__CIPSO__TAG_HDR_LEN, (
                f"Each CIPSO tag must be at least {IP4__OPTION__CIPSO__TAG_HDR_LEN} "
                f"bytes (type + length). Got tag #{index}: {tag!r}"
            )
            assert tag[1] == len(tag), (
                f"Each CIPSO tag's length byte must equal its actual length. "
                f"Got tag #{index}: tag[1]={tag[1]} actual_len={len(tag)}"
            )

        total_len = IP4__OPTION__CIPSO__HDR_LEN + IP4__OPTION__CIPSO__DOI_LEN + sum(len(tag) for tag in self.tags)
        assert total_len <= 255, f"The total CIPSO option length must fit in a single length byte. " f"Got: {total_len}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", total_len)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 CIPSO option log string.
        """

        return f"cipso doi={self.doi} tags=" f"[{', '.join(tag.hex() for tag in self.tags)}]"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 CIPSO option as a memoryview.
        """

        struct.pack_into(
            IP4__OPTION__CIPSO__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len,
            self.doi,
        )

        offset = IP4__OPTION__CIPSO__HDR_LEN + IP4__OPTION__CIPSO__DOI_LEN
        for tag in self.tags:
            buffer[offset : offset + len(tag)] = tag
            offset += len(tag)

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv4 CIPSO option before parsing it.
        """

        # FIPS-188 §4 / Linux net/ipv4/cipso_ipv4.c::cipso_v4_validate —
        # CIPSO option carries a 2-byte header (type + length) plus a
        # 4-byte DOI; shortest legal CIPSO has zero tags = 6 bytes.
        if (value := buffer[1]) < IP4__OPTION__CIPSO__MIN_LEN:
            raise Ip4IntegrityError(
                f"The IPv4 CIPSO option length must be at least " f"{IP4__OPTION__CIPSO__MIN_LEN} bytes. Got: {value!r}"
            )

        # RFC 791 §3.1 — option length MUST NOT exceed the buffer
        # available.
        if (value := buffer[1]) > len(buffer):
            raise Ip4IntegrityError(
                "The IPv4 CIPSO option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # FIPS-188 §A.3 / Linux cipso_v4_validate — walk the tag list
        # past the DOI and verify each tag's 2-byte (type+length)
        # header is well-formed and fits within the option boundary.
        offset = IP4__OPTION__CIPSO__HDR_LEN + IP4__OPTION__CIPSO__DOI_LEN
        end = buffer[1]
        while offset < end:
            if end - offset < IP4__OPTION__CIPSO__TAG_HDR_LEN:
                raise Ip4IntegrityError(
                    "An IPv4 CIPSO tag must be at least "
                    f"{IP4__OPTION__CIPSO__TAG_HDR_LEN} bytes "
                    f"(type + length). Got remaining: {end - offset}"
                )
            tag_len = buffer[offset + 1]
            if tag_len < IP4__OPTION__CIPSO__TAG_HDR_LEN:
                raise Ip4IntegrityError(
                    "An IPv4 CIPSO tag's length byte must be at least "
                    f"{IP4__OPTION__CIPSO__TAG_HDR_LEN}. Got: {tag_len}"
                )
            if offset + tag_len > end:
                raise Ip4IntegrityError(
                    "An IPv4 CIPSO tag's length byte must not extend past the "
                    f"option boundary. Got tag at offset {offset}: tag_len={tag_len}, "
                    f"option_end={end}"
                )
            offset += tag_len

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv4 CIPSO option from buffer.
        """

        assert (value := len(buffer)) >= IP4__OPTION__CIPSO__MIN_LEN, (
            f"The minimum length of the IPv4 CIPSO option must be "
            f"{IP4__OPTION__CIPSO__MIN_LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip4OptionType.CIPSO), (
            f"The IPv4 CIPSO option type must be {Ip4OptionType.CIPSO!r}. " f"Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        doi = int.from_bytes(bytes(buffer[2:6]))
        tags: list[bytes] = []
        offset = IP4__OPTION__CIPSO__HDR_LEN + IP4__OPTION__CIPSO__DOI_LEN
        end = buffer[1]
        while offset < end:
            tag_len = buffer[offset + 1]
            tags.append(bytes(buffer[offset : offset + tag_len]))
            offset += tag_len

        return cls(doi=doi, tags=tags)
