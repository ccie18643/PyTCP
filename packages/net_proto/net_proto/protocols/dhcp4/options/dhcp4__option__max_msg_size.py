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
This module contains the DHCPv4 Maximum DHCP Message Size option
support code (RFC 2132 §9.10).

net_proto/protocols/dhcp4/options/dhcp4__option__max_msg_size.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Maximum DHCP Message Size option [RFC 2132 §9.10].
#
#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 57  |   Length = 2  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       Maximum DHCP message size we are prepared to accept     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

DHCP4__OPTION__MAX_MSG_SIZE__LEN = 4
DHCP4__OPTION__MAX_MSG_SIZE__STRUCT = "! BB H"

# Per RFC 2132 §9.10 the option value MUST be at least 576 — the
# RFC 2131 §2 baseline-message-size minimum every client MUST be
# able to receive.
DHCP4__OPTION__MAX_MSG_SIZE__MIN: int = 576


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionMaxMsgSize(Dhcp4Option):
    """
    The DHCPv4 Maximum DHCP Message Size option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.MAX_MSG_SIZE,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__MAX_MSG_SIZE__LEN,
    )

    max_msg_size: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Maximum DHCP Message Size option fields.
        """

        assert is_uint16(
            self.max_msg_size
        ), f"The 'max_msg_size' field must be a 16-bit unsigned integer. Got: {self.max_msg_size}"
        assert self.max_msg_size >= DHCP4__OPTION__MAX_MSG_SIZE__MIN, (
            f"The 'max_msg_size' field must be at least "
            f"{DHCP4__OPTION__MAX_MSG_SIZE__MIN} bytes per RFC 2132 §9.10. "
            f"Got: {self.max_msg_size}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Maximum DHCP Message Size option log string.
        """

        return f"max_msg_size {self.max_msg_size}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Maximum DHCP Message Size option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__MAX_MSG_SIZE__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            int(self.max_msg_size),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Maximum DHCP Message Size option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) != DHCP4__OPTION__MAX_MSG_SIZE__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Maximum DHCP Message Size option length value must be "
                f"{DHCP4__OPTION__MAX_MSG_SIZE__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Maximum DHCP Message Size option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 2132 §9.10 — the option value MUST be at least 576
        # octets (the RFC 2131 §2 baseline-message-size floor every
        # client MUST be prepared to receive). Mirror the
        # dataclass `__post_init__` assert here so a hostile wire
        # frame raises a typed `Dhcp4IntegrityError` before
        # `cls(int.from_bytes(...))` construction would otherwise
        # produce a bare `AssertionError`.
        if (value := int.from_bytes(buffer[2:4], "big")) < DHCP4__OPTION__MAX_MSG_SIZE__MIN:
            raise Dhcp4IntegrityError(
                f"The DHCPv4 Maximum DHCP Message Size option value must be at least "
                f"{DHCP4__OPTION__MAX_MSG_SIZE__MIN} bytes (RFC 2132 §9.10). Got: {value}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Maximum DHCP Message Size option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Maximum DHCP Message Size option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.MAX_MSG_SIZE), (
            f"The DHCPv4 Maximum DHCP Message Size option type must be "
            f"{Dhcp4OptionType.MAX_MSG_SIZE!r}. Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(int.from_bytes(buffer[2:4], "big"))
