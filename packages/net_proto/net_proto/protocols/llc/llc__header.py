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
This module contains the IEEE 802.2 LLC (Logical Link
Control) U-frame header class. PyTCP supports the 1-byte
Control U-frame form (sufficient for RFC 1042 SNAP, STP /
RSTP / MSTP BPDUs, and the XID / TEST commands); I-frame
and S-frame variants with 2-byte Control are deliberately
out of scope (Type 2 connection-oriented LLC has no IP
consumer in modern networks).

net_proto/protocols/llc/llc__header.py

ver 3.0.9
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.lib.proto_struct import ProtoStruct
from net_proto.protocols.llc.llc__enums import LlcControl, LlcSap

# IEEE 802.2 LLC U-frame header.
#
# +-+-+-+-+-+-+-+-+
# |     DSAP      |
# +-+-+-+-+-+-+-+-+
# |     SSAP      |
# +-+-+-+-+-+-+-+-+
# |    Control    |
# +-+-+-+-+-+-+-+-+
#
# DSAP   — Destination Service Access Point (8 bits; LSB
#          carries I/G individual/group indicator).
# SSAP   — Source Service Access Point (8 bits; LSB
#          carries C/R command/response indicator).
# Control — 1-byte U-frame Control (PyTCP supports
#          U-frame only; the low 2 bits MUST be 0b11 for a
#          well-formed U-frame). For UI commands (the
#          dominant case on real networks) Control = 0x03.

LLC__HEADER__LEN: int = 3
LLC__HEADER__STRUCT: str = "! BBB"


@dataclass(frozen=True, kw_only=True, slots=True)
class LlcHeader(ProtoStruct):
    """
    The IEEE 802.2 LLC U-frame header.
    """

    dsap: LlcSap
    ssap: LlcSap
    control: LlcControl

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the LLC header fields.
        """

        assert isinstance(self.dsap, LlcSap), f"The 'dsap' field must be a LlcSap. Got: {type(self.dsap)!r}"
        assert isinstance(self.ssap, LlcSap), f"The 'ssap' field must be a LlcSap. Got: {type(self.ssap)!r}"
        assert isinstance(
            self.control, LlcControl
        ), f"The 'control' field must be a LlcControl. Got: {type(self.control)!r}"
        assert is_uint8(int(self.dsap)), f"The 'dsap' field must be an 8-bit unsigned integer. Got: {int(self.dsap)!r}"
        assert is_uint8(int(self.ssap)), f"The 'ssap' field must be an 8-bit unsigned integer. Got: {int(self.ssap)!r}"
        assert is_uint8(
            int(self.control)
        ), f"The 'control' field must be an 8-bit unsigned integer. Got: {int(self.control)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the LLC header length.
        """

        return LLC__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the LLC header as a memoryview.
        """

        struct.pack_into(
            LLC__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.dsap),
            int(self.ssap),
            int(self.control),
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the LLC header from buffer.
        """

        dsap, ssap, control = struct.unpack(LLC__HEADER__STRUCT, buffer[:LLC__HEADER__LEN])

        return cls(
            dsap=LlcSap.from_int(dsap),
            ssap=LlcSap.from_int(ssap),
            control=LlcControl.from_int(control),
        )


class LlcHeaderProperties(ABC):
    """
    Properties used to access the LLC header fields.
    """

    _header: LlcHeader

    @property
    def dsap(self) -> LlcSap:
        """
        Get the LLC header 'dsap' field.
        """

        return self._header.dsap

    @property
    def ssap(self) -> LlcSap:
        """
        Get the LLC header 'ssap' field.
        """

        return self._header.ssap

    @property
    def control(self) -> LlcControl:
        """
        Get the LLC header 'control' field.
        """

        return self._header.control
