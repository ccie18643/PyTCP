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
This module contains the ICMPv6 ND RA Flags option support code
(RFC 5175). The option carries a 48-bit reserved flag-bits
field for future allocation by the IETF; PyTCP parses and
emits it opaquely so the wire format round-trips even though
no bits are currently consumed by the host.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__ra_flags.py

ver 3.0.10
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND RA Flags option [RFC 5175 §3].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |        Bit fields available   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       for assignment                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__RA_FLAGS__LEN = 8
ICMP6__ND__OPTION__RA_FLAGS__FLAGS_BYTES = 6
ICMP6__ND__OPTION__RA_FLAGS__FLAGS_MAX = (1 << 48) - 1


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionRaFlags(Icmp6NdOption):
    """
    The ICMPv6 ND RA Flags option support class (RFC 5175 §3).
    Carries a 48-bit big-endian flag-bits field reserved for
    future allocation; no flags are currently consumed by the
    host. Stored as a single 'int' for forward-compat — when
    the IETF allocates a flag bit, callers can mask it out of
    the integer.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.RA_FLAGS_EXTENSION,
    )
    len: int = field(
        repr=False,
        init=False,
        default=ICMP6__ND__OPTION__RA_FLAGS__LEN,
    )

    flags: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND RA Flags option fields.
        """

        assert (
            0 <= self.flags <= ICMP6__ND__OPTION__RA_FLAGS__FLAGS_MAX
        ), f"The 'flags' field must be a 48-bit unsigned integer. Got: {self.flags!r}"

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND RA Flags option log string.
        """

        return f"ra_flags (0x{self.flags:012x})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND RA Flags option as a memoryview.

        Per RFC 5175 §4 senders MUST emit Length=1 (8 bytes
        total). 'self.len' may be larger when this instance was
        parsed from a future-RFC-extended frame (so the option-
        dispatcher loop knows how to skip the unrecognized tail
        on receive), but the canonical-sender output is always
        the 8-byte form.
        """

        buffer = bytearray(ICMP6__ND__OPTION__RA_FLAGS__LEN)
        buffer[0] = int(self.type)
        buffer[1] = ICMP6__ND__OPTION__RA_FLAGS__LEN >> 3
        buffer[2 : 2 + ICMP6__ND__OPTION__RA_FLAGS__FLAGS_BYTES] = self.flags.to_bytes(
            ICMP6__ND__OPTION__RA_FLAGS__FLAGS_BYTES,
            byteorder="big",
        )
        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND RA Flags option before
        parsing it. Per RFC 5175 §4 receivers MUST accept any
        length ≥ 1 (8 bytes total) — a future RFC may extend
        the option with additional flag bytes — and MUST ignore
        the option if Length is less than 1.
        """

        encoded_len = buffer[1] << 3
        if encoded_len < ICMP6__ND__OPTION__RA_FLAGS__LEN:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND RA Flags option length value must be at least "
                f"{ICMP6__ND__OPTION__RA_FLAGS__LEN} bytes. Got: {encoded_len!r}"
            )

        if encoded_len > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND RA Flags option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {encoded_len!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND RA Flags option from buffer.

        Per RFC 5175 §4 the parser captures the first 6 flag
        bytes (the recognized region) and stores the on-wire
        Length so the options-dispatcher loop advances past any
        unrecognized tail. The assembler still emits Length=1
        for any instance — senders MUST conform to this
        specification's fixed length.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND RA Flags option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.RA_FLAGS_EXTENSION), (
            f"The ICMPv6 ND RA Flags option type must be {Icmp6NdOptionType.RA_FLAGS_EXTENSION!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        flags = int.from_bytes(
            bytes(buffer[2 : 2 + ICMP6__ND__OPTION__RA_FLAGS__FLAGS_BYTES]),
            byteorder="big",
        )
        instance = cls(flags=flags)

        # Stash the actual on-wire length so the option-
        # dispatcher loop can skip over any unrecognized tail
        # bytes from a future-RFC extension. The dataclass'
        # default len=8 is preserved for instances built via
        # the kw-only constructor.
        encoded_len = buffer[1] << 3
        if encoded_len > ICMP6__ND__OPTION__RA_FLAGS__LEN:
            object.__setattr__(instance, "len", encoded_len)

        return instance
