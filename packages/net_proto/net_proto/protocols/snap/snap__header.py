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
This module contains the SNAP (Sub-Network Access Protocol)
header class. SNAP rides directly on top of an LLC header
whose DSAP and SSAP both equal 0xAA (`LlcSap.SNAP`); the
SNAP header itself is 5 bytes: a 3-byte OUI followed by a
2-byte protocol identifier. When OUI = 0x000000 the protocol
ID is interpreted as a standard EtherType (RFC 1042
§"Header Format"); when OUI is non-zero the protocol ID
belongs to the OUI-owner's protocol sub-space (e.g. CDP /
VTP / DTP under Cisco's OUI 0x00000C).

net_proto/protocols/snap/snap__header.py

ver 3.0.9
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.lib.proto_struct import ProtoStruct
from net_proto.protocols.snap.snap__enums import SnapOui

# SNAP header (RFC 1042 §"Header Format").
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  OUI (24 bits)                |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       Protocol ID / EtherType (16 bits)       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# OUI         — 24-bit IEEE Organizationally Unique
#               Identifier. 0x000000 means "the protocol
#               ID is a standard EtherType" (RFC 1042
#               canonical case for IP-over-SNAP).
# Protocol ID — 16-bit identifier. When OUI = 0 this is
#               an EtherType; otherwise it is owned by
#               the OUI holder's protocol registry.

SNAP__HEADER__LEN: int = 5
SNAP__HEADER__STRUCT: str = "! 3s H"


@dataclass(frozen=True, kw_only=True, slots=True)
class SnapHeader(ProtoStruct):
    """
    The SNAP header.
    """

    oui: int  # 24-bit unsigned integer.
    pid: int  # 16-bit unsigned integer (EtherType when oui==0).

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the SNAP header fields.
        """

        assert 0 <= self.oui <= 0xFFFFFF, f"The 'oui' field must be a 24-bit unsigned integer. Got: {self.oui!r}"
        assert is_uint16(self.pid), f"The 'pid' field must be a 16-bit unsigned integer. Got: {self.pid!r}"

    @override
    def __len__(self) -> int:
        """
        Get the SNAP header length.
        """

        return SNAP__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the SNAP header as a memoryview.
        """

        struct.pack_into(
            SNAP__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            self.oui.to_bytes(3),
            self.pid,
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the SNAP header from buffer.
        """

        oui_bytes, pid = struct.unpack(SNAP__HEADER__STRUCT, buffer[:SNAP__HEADER__LEN])

        return cls(
            oui=int.from_bytes(oui_bytes),
            pid=pid,
        )

    @property
    def is_encapsulated_ethertype(self) -> bool:
        """
        Return True when the SNAP frame is an RFC 1042
        encapsulated-EtherType frame (OUI = 0x000000); the
        PID is interpretable as a standard EtherType in
        this case.
        """

        return self.oui == SnapOui.ENCAP_ETHERTYPE


class SnapHeaderProperties(ABC):
    """
    Properties used to access the SNAP header fields.
    """

    _header: SnapHeader

    @property
    def oui(self) -> int:
        """
        Get the SNAP header 'oui' field.
        """

        return self._header.oui

    @property
    def pid(self) -> int:
        """
        Get the SNAP header 'pid' field.
        """

        return self._header.pid
