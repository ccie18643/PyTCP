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
This module contains the DHCPv4 Host Name option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__host_name.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Host Name option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code=12   |     Len=N     |           Hostname           ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__HOST_NAME__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionHostName(Dhcp4Option):
    """
    The DHCPv4 Host Name option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.HOST_NAME,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    host_name: str

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Host Name option fields.
        """

        assert isinstance(self.host_name, str), f"The 'host_name' field must be a str. Got: {type(self.host_name)!r}"

        # Compute the wire-format byte count, NOT the Python char
        # count. RFC 2132 §3.14 specifies the option as a string,
        # and PyTCP serializes via `encode("utf-8")` — for any
        # non-ASCII character the byte length exceeds the char
        # length, and the wire frame's length byte must agree
        # with the trailing data byte count.
        byte_len = len(self.host_name.encode("utf-8"))

        assert byte_len >= 1, (
            f"The 'host_name' field must carry at least 1 byte (RFC 2132 §3.14 "
            f"minimum length 1). Got: {byte_len} bytes"
        )

        assert byte_len <= 255, (
            f"The 'host_name' field encoded length must fit in a uint8 (RFC 2132 §3.14 "
            f"length byte). Got: {byte_len} bytes"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + byte_len)

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Host Name option log string.
        """

        return f"host_name {self.host_name}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Host Name option as a memoryview.
        """

        # Use the encoded byte sequence for both the length byte
        # and the trailing data so the wire frame is self-
        # consistent for non-ASCII host names (see __post_init__
        # for the byte-count rationale).
        encoded = self.host_name.encode("utf-8")
        buffer = bytearray(len(self))

        struct.pack_into(
            DHCP4__OPTION__HOST_NAME__STRUCT,
            buffer,
            0,
            int(self.type),
            len(encoded),
        )
        buffer[DHCP4__OPTION__LEN:] = encoded

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Host Name option before parsing it.
        """

        if (value := buffer[1]) < 1:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Host Name option minimum length is 1 octet " f"(RFC 2132 §3.14). Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Host Name option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 2132 §3.14 does not pin the encoding, but the option's
        # `host_name` field is a Python `str` decoded via
        # `bytes.decode("utf-8")` in `from_buffer`. A hostile wire
        # frame whose payload is not valid UTF-8 would otherwise
        # raise `UnicodeDecodeError` past the option-level
        # integrity boundary. Pre-validate here so a typed
        # `Dhcp4IntegrityError` surfaces instead.
        try:
            bytes(buffer[2 : 2 + buffer[1]]).decode("utf-8")
        except UnicodeDecodeError as error:
            raise Dhcp4IntegrityError(
                f"The DHCPv4 Host Name option payload must be valid UTF-8. Got: {error}"
            ) from error

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Host Name option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Host Name option must be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.HOST_NAME), (
            f"The DHCPv4 Host Name option type must be {Dhcp4OptionType.HOST_NAME!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls((bytes(buffer[2 : 2 + buffer[1]])).decode("utf-8"))  # Note: Conversion: memoryview -> bytes
