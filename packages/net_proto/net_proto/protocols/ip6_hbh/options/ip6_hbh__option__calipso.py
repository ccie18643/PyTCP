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
This module contains the IPv6 HBH CALIPSO (Common Architecture Label
IPv6 Security Option) support code (RFC 5570 / Linux NetLabel).

Shallow representation: parses the RFC 5570 §4 fixed fields (DOI,
Sens Level, Checksum, Compartment Bitmap) but does not validate the
CRC-16 checksum nor decode the bitmap semantically — PyTCP has no
NetLabel/SELinux MLS consumer to feed. The parsed bytes round-trip
byte-for-byte for Phase-2 forwarder re-emission.

net_proto/protocols/ip6_hbh/options/ip6_hbh__option__calipso.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8, is_uint16, is_uint32
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import (
    IP6_HBH__OPTION__LEN,
    Ip6HbhOption,
    Ip6HbhOptionType,
)

# The IPv6 HBH CALIPSO option [RFC 5570 §4].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Type  |  Opt Data Len |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   CALIPSO Domain of Interp.   |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Cmpt Length  |   Sens Level  |     Checksum (CRC-16)         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Compartment Bitmap (Optional; variable length)            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Type=0x07 (top-2-bits=00 -> skip-if-unknown), variable length.
# Cmpt Length is the compartment-bitmap length in 32-bit units;
# bitmap byte length = cmpt_length * 4.

# 8-byte fixed prefix: DOI(4) + Cmpt Length(1) + Sens Level(1) + Checksum(2).
IP6_HBH__OPTION__CIPSO__FIXED_DATA_LEN = 8
IP6_HBH__OPTION__CIPSO__FIXED_LEN = IP6_HBH__OPTION__LEN + IP6_HBH__OPTION__CIPSO__FIXED_DATA_LEN
IP6_HBH__OPTION__CIPSO__STRUCT = "! BBLBBH"
IP6_HBH__OPTION__CIPSO__BITMAP_UNIT = 4  # Cmpt Length is in 32-bit (4-byte) units.


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip6HbhOptionCalipso(Ip6HbhOption):
    """
    The IPv6 HBH CALIPSO option support class.

    'cmpt_length' is computed automatically from the compartment
    bitmap byte length. The CRC-16 checksum is preserved on the
    wire but not validated — Linux NetLabel computes it; PyTCP
    has no MLS consumer to feed.
    """

    type: Ip6HbhOptionType = field(
        repr=False,
        init=False,
        default=Ip6HbhOptionType.CALIPSO,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    doi: int
    sens_level: int
    checksum: int
    compartment_bitmap: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 HBH CALIPSO option fields.
        """

        assert is_uint32(self.doi), f"The 'doi' field must be a 32-bit unsigned integer. Got: {self.doi!r}"
        assert is_uint8(
            self.sens_level
        ), f"The 'sens_level' field must be an 8-bit unsigned integer. Got: {self.sens_level!r}"
        assert is_uint16(
            self.checksum
        ), f"The 'checksum' field must be a 16-bit unsigned integer. Got: {self.checksum!r}"

        bitmap_len = len(self.compartment_bitmap)
        assert bitmap_len % IP6_HBH__OPTION__CIPSO__BITMAP_UNIT == 0, (
            f"The compartment bitmap length must be a multiple of "
            f"{IP6_HBH__OPTION__CIPSO__BITMAP_UNIT} bytes. Got: {bitmap_len}"
        )

        total_len = IP6_HBH__OPTION__CIPSO__FIXED_LEN + bitmap_len

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", total_len)

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @property
    def cmpt_length(self) -> int:
        """
        Get the compartment-bitmap length in 32-bit units (the
        Cmpt Length wire field).
        """

        return len(self.compartment_bitmap) // IP6_HBH__OPTION__CIPSO__BITMAP_UNIT

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 HBH CALIPSO option log string.
        """

        return (
            f"calipso doi={self.doi} sens={self.sens_level} " f"cmpt={self.cmpt_length} checksum=0x{self.checksum:04x}"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 HBH CALIPSO option as a memoryview.
        """

        struct.pack_into(
            IP6_HBH__OPTION__CIPSO__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len - IP6_HBH__OPTION__LEN,
            self.doi,
            self.cmpt_length,
            self.sens_level,
            self.checksum,
        )

        buffer[IP6_HBH__OPTION__CIPSO__FIXED_LEN:] = self.compartment_bitmap

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv6 HBH CALIPSO option before
        parsing it. Hostile-wire defense-in-depth so an
        Opt Data Len / Cmpt Length mismatch does not leak as a
        bare AssertionError past the IPv6 chain walker's
        PacketValidationError catch.
        """

        # RFC 5570 §4 — Opt Data Len = 8 (fixed DOI + Cmpt Length
        # + Sens Level + Checksum prefix) + cmpt_length * 4
        # (compartment bitmap in 32-bit units). A mismatch means
        # the bitmap is either truncated or over-claimed.
        opt_data_len = buffer[1]
        cmpt_length = buffer[6]
        bitmap_len = cmpt_length * IP6_HBH__OPTION__CIPSO__BITMAP_UNIT
        if opt_data_len != IP6_HBH__OPTION__CIPSO__FIXED_DATA_LEN + bitmap_len:
            raise Ip6HbhIntegrityError(
                f"The IPv6 HBH CALIPSO Opt Data Len must equal "
                f"{IP6_HBH__OPTION__CIPSO__FIXED_DATA_LEN} + cmpt_length * "
                f"{IP6_HBH__OPTION__CIPSO__BITMAP_UNIT}. Got: opt_data_len={opt_data_len}, "
                f"cmpt_length={cmpt_length}"
            )

        # RFC 5570 §4 / RFC 8200 §4.2 — option length MUST NOT
        # exceed the buffer available. The container's
        # validate_integrity already guarantees this for the
        # block-walk, but the per-option check is defense-in-depth
        # for direct from_buffer callers.
        if len(buffer) < IP6_HBH__OPTION__LEN + opt_data_len:
            raise Ip6HbhIntegrityError(
                "The buffer must hold the full CALIPSO option declared by Opt Data Len. "
                f"Got: opt_data_len={opt_data_len}, buffer_len={len(buffer)}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 HBH CALIPSO option from buffer.
        """

        assert (value := len(buffer)) >= IP6_HBH__OPTION__CIPSO__FIXED_LEN, (
            f"The minimum length of the IPv6 HBH CALIPSO option must be "
            f"{IP6_HBH__OPTION__CIPSO__FIXED_LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip6HbhOptionType.CALIPSO), (
            f"The IPv6 HBH CALIPSO option type must be {Ip6HbhOptionType.CALIPSO!r}. "
            f"Got: {Ip6HbhOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        cmpt_length = buffer[6]
        bitmap_len = cmpt_length * IP6_HBH__OPTION__CIPSO__BITMAP_UNIT

        doi = int.from_bytes(bytes(buffer[2:6]))
        sens_level = buffer[7]
        checksum = int.from_bytes(bytes(buffer[8:10]))
        compartment_bitmap = bytes(
            buffer[IP6_HBH__OPTION__CIPSO__FIXED_LEN : IP6_HBH__OPTION__CIPSO__FIXED_LEN + bitmap_len]
        )

        return cls(
            doi=doi,
            sens_level=sens_level,
            checksum=checksum,
            compartment_bitmap=compartment_bitmap,
        )
