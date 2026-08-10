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
This module contains the DHCPv4 Option Overload option support
code (RFC 2132 §9.3). Servers use this option to signal that
the legacy BOOTP 'sname' and/or 'file' header fields carry
additional options rather than their nominal values; PyTCP
parses these as part of the inbound options pipeline.

net_proto/protocols/dhcp4/options/dhcp4__option__overload.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Option Overload option [RFC 2132 §9.3].
#
#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 52  |   Length = 1  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Value=1/2/3 |
# +-+-+-+-+-+-+-+-+
#
# Value 1: 'file' field carries additional options.
# Value 2: 'sname' field carries additional options.
# Value 3: both 'file' and 'sname' carry additional options.

DHCP4__OPTION__OVERLOAD__LEN = 3
DHCP4__OPTION__OVERLOAD__STRUCT = "! BB B"


class Dhcp4OptionOverloadValue(ProtoEnumByte):
    """
    The DHCPv4 Option Overload option 'value' codepoint (RFC 2132 §9.3).
    """

    FILE = 1  # 'file' field carries additional options.
    SNAME = 2  # 'sname' field carries additional options.
    BOTH = 3  # both 'file' and 'sname' carry additional options.


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionOverload(Dhcp4Option):
    """
    The DHCPv4 Option Overload option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.OPTION_OVERLOAD,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__OVERLOAD__LEN,
    )

    value: Dhcp4OptionOverloadValue

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Option Overload option fields.
        """

        assert not self.value.is_unknown, (
            f"The 'value' field must be a known Dhcp4OptionOverloadValue "
            f"(FILE/SNAME/BOTH) per RFC 2132 §9.3. Got: {self.value!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Option Overload option log string.
        """

        return f"option_overload {int(self.value)}"

    @property
    def includes_file(self) -> bool:
        """
        Return True when the 'file' BOOTP field carries additional options.
        """

        return self.value in (
            Dhcp4OptionOverloadValue.FILE,
            Dhcp4OptionOverloadValue.BOTH,
        )

    @property
    def includes_sname(self) -> bool:
        """
        Return True when the 'sname' BOOTP field carries additional options.
        """

        return self.value in (
            Dhcp4OptionOverloadValue.SNAME,
            Dhcp4OptionOverloadValue.BOTH,
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Option Overload option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__OVERLOAD__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            int(self.value),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Option Overload option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) != DHCP4__OPTION__OVERLOAD__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Option Overload option length value must be "
                f"{DHCP4__OPTION__OVERLOAD__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Option Overload option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        if (value := buffer[2]) not in Dhcp4OptionOverloadValue.get_known_values():
            raise Dhcp4IntegrityError(
                f"The DHCPv4 Option Overload value must be 1, 2, or 3. Got: {value!r}",
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Option Overload option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Option Overload option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.OPTION_OVERLOAD), (
            f"The DHCPv4 Option Overload option type must be "
            f"{Dhcp4OptionType.OPTION_OVERLOAD!r}. Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(Dhcp4OptionOverloadValue(buffer[2]))
