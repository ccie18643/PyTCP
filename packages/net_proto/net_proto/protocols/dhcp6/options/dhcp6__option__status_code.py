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
This module contains the DHCPv6 Status Code option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__status_code.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp6.dhcp6__enums import Dhcp6StatusCode
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 Status Code option [RFC 8415 §21.13].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    OPTION_STATUS_CODE = 13    |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          status-code          |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
# .                         status-message                        .
# .                       (UTF-8, variable)                       .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__STATUS_CODE__STRUCT = "! HH H"
DHCP6__OPTION__STATUS_CODE__CODE__LEN = 2


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp6OptionStatusCode(Dhcp6Option):
    """
    The DHCPv6 Status Code option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.STATUS_CODE,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    status_code: Dhcp6StatusCode
    status_message: str = ""

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 Status Code option fields.
        """

        assert isinstance(
            self.status_code, Dhcp6StatusCode
        ), f"The 'status_code' field must be a Dhcp6StatusCode. Got: {type(self.status_code)!r}"

        assert isinstance(
            self.status_message, str
        ), f"The 'status_message' field must be a string. Got: {type(self.status_message)!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "len",
            DHCP6__OPTION__LEN + DHCP6__OPTION__STATUS_CODE__CODE__LEN + len(self.status_message.encode("utf-8")),
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 Status Code option log string.
        """

        return f"status_code {self.status_code}" + (f" ({self.status_message})" if self.status_message else "")

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 Status Code option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__STATUS_CODE__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
            int(self.status_code),
        )
        buffer[DHCP6__OPTION__LEN + DHCP6__OPTION__STATUS_CODE__CODE__LEN :] = self.status_message.encode("utf-8")

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 Status Code option before parsing it.
        """

        option_len = int.from_bytes(buffer[2:4])

        if option_len < DHCP6__OPTION__STATUS_CODE__CODE__LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 Status Code option must carry the 2-octet status-code field "
                f"(RFC 8415 §21.13). Got: {option_len!r}"
            )

        if (value := DHCP6__OPTION__LEN + option_len) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 Status Code option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 Status Code option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 Status Code option must "
            f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.STATUS_CODE), (
            f"The DHCPv6 Status Code option type must be {Dhcp6OptionType.STATUS_CODE!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        option_len = int.from_bytes(buffer[2:4])
        code_offset = DHCP6__OPTION__LEN
        message_offset = code_offset + DHCP6__OPTION__STATUS_CODE__CODE__LEN

        return cls(
            Dhcp6StatusCode.from_int(int.from_bytes(buffer[code_offset:message_offset])),
            # RFC 8415 §21.13 — status-message is a UTF-8 string for
            # display. Decode tolerantly ('errors="replace"') so a
            # malformed-UTF-8 message does not turn a server REPLY into
            # a hostile-wire rejection (the field is advisory only).
            bytes(buffer[message_offset : code_offset + option_len]).decode("utf-8", errors="replace"),
        )
