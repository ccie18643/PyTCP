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
This module contains the ICMPv6 ND Nonce option support code
(RFC 3971 §5.3.2; consumed by RFC 7527 §4.1 Enhanced DAD). The
option carries a single-use random value the sender uses to
detect loop-hairpin echoes of its own DAD probes.

PyTCP emits the option only on DAD probes (when 'icmp6.enhanced_dad'
is non-zero); receivers compare the inbound nonce against the
set of nonces the host has emitted during the current DAD
session.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__nonce.py

ver 3.0.9
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

# The ICMPv6 ND Nonce option [RFC 3971 §5.3.2 / RFC 7527 §4.1].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |    Length     |              Nonce            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Wire layout: type(1) + length(1) + nonce(6) = 8 bytes total
# (length-field = 1 in 8-octet units). RFC 3971 allows longer
# nonces with length-field > 1, but Enhanced DAD per RFC 7527 §3
# uses 6-byte nonces exclusively; PyTCP emits and accepts that
# canonical size.
ICMP6__ND__OPTION__NONCE__LEN = 8
ICMP6__ND__OPTION__NONCE__NONCE_BYTES = 6


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionNonce(Icmp6NdOption):
    """
    The ICMPv6 ND Nonce option support class (RFC 3971 §5.3.2).
    Carries a 6-byte single-use random value used by the
    Enhanced DAD algorithm (RFC 7527 §4) to distinguish a
    looped-back DAD probe from a genuine duplicate-address
    conflict.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.NONCE,
    )
    len: int = field(
        repr=False,
        init=False,
        default=ICMP6__ND__OPTION__NONCE__LEN,
    )

    nonce: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Nonce option fields.
        """

        assert isinstance(
            self.nonce, (bytes, bytearray)
        ), f"The 'nonce' field must be a bytes object. Got: {type(self.nonce)!r}"

        assert len(self.nonce) == ICMP6__ND__OPTION__NONCE__NONCE_BYTES, (
            f"The 'nonce' field must be exactly "
            f"{ICMP6__ND__OPTION__NONCE__NONCE_BYTES} bytes. "
            f"Got: {len(self.nonce)} bytes"
        )

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Nonce option log string.
        """

        return f"nonce (0x{self.nonce.hex()})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Nonce option as a memoryview.
        """

        buffer = bytearray(ICMP6__ND__OPTION__NONCE__LEN)
        buffer[0] = int(self.type)
        buffer[1] = ICMP6__ND__OPTION__NONCE__LEN >> 3
        buffer[2 : 2 + ICMP6__ND__OPTION__NONCE__NONCE_BYTES] = self.nonce
        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND Nonce option before parsing it.
        """

        if (value := buffer[1] << 3) < ICMP6__ND__OPTION__NONCE__LEN:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND Nonce option length value must be at least "
                f"{ICMP6__ND__OPTION__NONCE__LEN} bytes. Got: {value!r}"
            )

        if (value := buffer[1] << 3) > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Nonce option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Nonce option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND Nonce option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.NONCE), (
            f"The ICMPv6 ND Nonce option type must be {Icmp6NdOptionType.NONCE!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        nonce = bytes(buffer[2 : 2 + ICMP6__ND__OPTION__NONCE__NONCE_BYTES])

        return cls(nonce=nonce)
