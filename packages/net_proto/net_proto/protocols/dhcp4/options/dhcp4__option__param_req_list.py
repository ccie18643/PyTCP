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
This module contains the DHCPv4 Parameter Request List option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__param_req_list.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Parameter Request List option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code=55   |     Len=N     |  Option Code  |  Option Code  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Code  |  Option Code  | ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__PARAM_REQ_LIST__STRUCT = "! BB"
DHCP4__OPTION__PARAM_REQ_LIST__ELEMENT__LEN = 1
DHCP4__OPTION__PARAM_REQ_LIST__ELEMENT__STRUCT = "! B"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionParamReqList(Dhcp4Option):
    """
    The DHCPv4 Parameter Request List option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.PARAM_REQ_LIST,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    param_req_list: list[Dhcp4OptionType]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Parameter Request List option fields.
        """

        assert isinstance(
            self.param_req_list, list
        ), f"The 'param_req_list' field must be a list. Got: {type(self.param_req_list)!r}"

        assert all(isinstance(item, Dhcp4OptionType) for item in self.param_req_list), (
            f"The 'param_req_list' field must be a list of Dhcp4OptionType elements. "
            f"Got: {[type(element) for element in self.param_req_list]!r}"
        )

        assert len(self.param_req_list) >= 1, (
            f"The 'param_req_list' field must carry at least 1 entry (RFC 2132 §9.8 "
            f"minimum length 1 octet). Got: {len(self.param_req_list)}"
        )

        assert len(self.param_req_list) <= 255, (
            f"The 'param_req_list' field must carry at most 255 entries (RFC 2132 §9.8 "
            f"length is a single octet). Got: {len(self.param_req_list)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.param_req_list))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Parameter Request List option log string.
        """

        return f"param_req_list {[param.name for param in self.param_req_list]}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Parameter Request List option as a memoryview.
        """

        buffer = bytearray(len(self))

        struct.pack_into(
            DHCP4__OPTION__PARAM_REQ_LIST__STRUCT,
            buffer,
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
        )

        for index, option in enumerate(self.param_req_list):
            struct.pack_into(
                DHCP4__OPTION__PARAM_REQ_LIST__ELEMENT__STRUCT,
                buffer,
                DHCP4__OPTION__LEN + index * DHCP4__OPTION__PARAM_REQ_LIST__ELEMENT__LEN,
                int(option),
            )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Parameter Request List option before parsing it.
        """

        if (value := buffer[1]) < 1:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Parameter Request List option minimum length is 1 octet " f"(RFC 2132 §9.8). Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Parameter Request List option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Parameter Request List option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Parameter Request List option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.PARAM_REQ_LIST), (
            f"The DHCPv4 Parameter Request List option type must be {Dhcp4OptionType.PARAM_REQ_LIST!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls([Dhcp4OptionType.from_int(option) for option in buffer[2 : 2 + buffer[1]]])
