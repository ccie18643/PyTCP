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
This module contains the DHCPv4 Subnet Mask option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__subnet_mask.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip4Mask
from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Subnet Mask option [RFC 2132].

#                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                     |     Code = 1    |    Length = 4   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                Subnet Mask                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__SUBNET_MASK__LEN = 6
DHCP4__OPTION__SUBNET_MASK__STRUCT = "! BB 4s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionSubnetMask(Dhcp4Option):
    """
    The DHCPv4 Subnet Mask option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.SUBNET_MASK,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__SUBNET_MASK__LEN,
    )

    subnet_mask: Ip4Mask

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Subnet Mask option fields.
        """

        assert isinstance(
            self.subnet_mask, Ip4Mask
        ), f"The 'subnet_mask' field must be an Ip4Mask. Got: {type(self.subnet_mask)!r}"

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Subnet Mask option log string.
        """

        return f"subnet_mask {self.subnet_mask}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Subnet Mask option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__SUBNET_MASK__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            bytes(self.subnet_mask),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Subnet Mask option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) != DHCP4__OPTION__SUBNET_MASK__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Subnet Mask option length value must be "
                f"{DHCP4__OPTION__SUBNET_MASK__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Subnet Mask option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 950 §2.1 — a subnet mask MUST consist of a run of
        # high-order ones followed by a run of low-order zeros. The
        # `Ip4Mask` value-type constructor rejects non-contiguous
        # masks with `Ip4MaskFormatError` (caught at the parser-wrap
        # boundary), but mirroring the check here lets a hostile
        # mask surface as a typed `Dhcp4IntegrityError` with an
        # RFC-cited message before `Ip4Mask` construction runs.
        # Contiguity test: inverting the mask must produce a value
        # whose set bits form a single low-order run, i.e.
        # `inverted & (inverted + 1) == 0`.
        candidate = int.from_bytes(buffer[2:6])
        inverted = (~candidate) & 0xFFFFFFFF
        if inverted & (inverted + 1) != 0:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Subnet Mask must consist of contiguous high-order "
                f"ones (RFC 950 §2.1). Got: 0x{candidate:08x}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Subnet Mask option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Subnet Mask option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.SUBNET_MASK), (
            f"The DHCPv4 Subnet Mask option type must be {Dhcp4OptionType.SUBNET_MASK!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(Ip4Mask(buffer[2:6]))
