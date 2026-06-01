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
This module contains the DHCPv4 Requested IP Address option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__req_ip_addr.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Requested IP Address option [RFC 2132].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 50  |   Length = 4  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Requested IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__REQ_IP_ADDR__LEN = 6
DHCP4__OPTION__REQ_IP_ADDR__STRUCT = "! BB 4s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionReqIpAddr(Dhcp4Option):
    """
    The DHCPv4 Requested IP Address option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.REQ_IP_ADDR,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__REQ_IP_ADDR__LEN,
    )

    req_ip_addr: Ip4Address

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Requested IP Address option fields.
        """

        assert isinstance(
            self.req_ip_addr, Ip4Address
        ), f"The 'req_ip_addr' field must be an Ip4Address. Got: {type(self.req_ip_addr)!r}"

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Requested IP Address option log string.
        """

        return f"req_ip_addr {self.req_ip_addr}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Requested IP Address option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__REQ_IP_ADDR__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            bytes(self.req_ip_addr),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Requested IP Address option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) != DHCP4__OPTION__REQ_IP_ADDR__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Requested IP Address option length value must be "
                f"{DHCP4__OPTION__REQ_IP_ADDR__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Requested IP Address option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Requested IP Address option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Requested IP Address option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.REQ_IP_ADDR), (
            f"The DHCPv4 Requested IP Address option type must be {Dhcp4OptionType.REQ_IP_ADDR!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(Ip4Address(buffer[2:6]))
