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
This module contains the ICMPv6 ND DNS Search List (DNSSL) option
support code (RFC 8106 §5.2). Domain names are encoded per
RFC 1035 §3.1 (length-prefixed labels terminated by a zero
length octet) and the option is padded with zero octets to an
8-octet alignment.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__dnssl.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND DNS Search List option [RFC 8106 §5.2].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 31  |    Length     |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Lifetime                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# :                  Domain Names of DNS Search List              :
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__DNSSL__FIXED_LEN = 8
ICMP6__ND__OPTION__DNSSL__STRUCT__FIXED = "! BB H L"
ICMP6__ND__OPTION__DNSSL__OCTET_ALIGN = 8

# RFC 1035 §2.3.4: each DNS label is at most 63 octets.
ICMP6__ND__OPTION__DNSSL__MAX_LABEL_LEN = 63


def _encode_domain(domain: str) -> bytes:
    """
    Encode a single domain name as an RFC 1035 §3.1 label
    sequence terminated by a zero-length label.
    """

    parts: list[bytes] = []
    for label in domain.split("."):
        parts.append(bytes([len(label)]) + label.encode("ascii"))
    parts.append(b"\x00")  # null terminator
    return b"".join(parts)


def _decode_domains(buffer: Buffer, /) -> tuple[str, ...]:
    """
    Decode a DNSSL Domain Names blob into a tuple of dotted
    domain strings. Trailing zero bytes (8-octet alignment
    padding) are skipped. Malformed input — labels claiming to
    extend past the buffer, oversize labels, non-ASCII bytes —
    truncates parsing per RFC 8106 §5.2 ("a receiver MUST
    silently ignore any Search Domain Name field that contains
    one or more labels that are NOT well-formed").
    """

    domains: list[str] = []
    offset = 0
    plen = len(buffer)
    while offset < plen:
        if buffer[offset] == 0:
            # Either a zero-length label that terminates an empty
            # encoding (treat as padding) or trailing pad bytes.
            offset += 1
            continue
        labels: list[str] = []
        # Read labels of the current domain until the zero
        # terminator or end-of-buffer.
        while offset < plen and buffer[offset] != 0:
            label_len = buffer[offset]
            offset += 1
            if label_len > ICMP6__ND__OPTION__DNSSL__MAX_LABEL_LEN or offset + label_len > plen:
                # Malformed label — silently ignore the rest.
                return tuple(domains)
            try:
                labels.append(bytes(buffer[offset : offset + label_len]).decode("ascii"))
            except UnicodeDecodeError:
                return tuple(domains)
            offset += label_len
        # Skip the terminator zero byte if present.
        if offset < plen:
            offset += 1
        if labels:
            domains.append(".".join(labels))
    return tuple(domains)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionDnssl(Icmp6NdOption):
    """
    The ICMPv6 ND DNS Search List option support class
    (RFC 8106 §5.2). Carried in Router Advertisement messages
    to advertise zero or more DNS search-domain names with a
    single shared lifetime.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.DNSSL,
    )
    len: int = field(
        repr=True,
        init=False,
    )

    lifetime: int
    domains: tuple[str, ...] = ()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND DNSSL option fields
        and compute the on-wire byte length (header + padded
        domain encoding rounded up to 8-octet alignment).
        """

        assert is_uint32(
            self.lifetime
        ), f"The 'lifetime' field must be a 32-bit unsigned integer. Got: {self.lifetime!r}"

        for domain in self.domains:
            assert isinstance(domain, str), f"Every entry in 'domains' must be a string. Got: {type(domain)!r}"
            for label in domain.split("."):
                assert (
                    0 < len(label) <= ICMP6__ND__OPTION__DNSSL__MAX_LABEL_LEN
                ), f"Every DNSSL label must be 1..63 octets. Got: {label!r}"
                try:
                    label.encode("ascii")
                except UnicodeEncodeError:
                    assert (
                        False
                    ), (  # noqa: B011 - intentional assertion failure
                        f"DNSSL labels must be ASCII (RFC 8106 §3.1 IDNA constraint). Got: {label!r}"
                    )

        # Encoded domain bytes + 8-octet padding alignment.
        encoded = b"".join(_encode_domain(d) for d in self.domains)
        # Round up to 8-byte alignment for the encoded portion.
        align = ICMP6__ND__OPTION__DNSSL__OCTET_ALIGN
        padded_len = (len(encoded) + align - 1) // align * align
        wire_len = ICMP6__ND__OPTION__DNSSL__FIXED_LEN + padded_len
        object.__setattr__(self, "len", wire_len)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND DNSSL option log string.
        """

        return f"dnssl (lifetime {self.lifetime}, domains [{', '.join(self.domains)}])"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND DNSSL option as a memoryview.
        """

        buffer = bytearray(len(self))
        struct.pack_into(
            ICMP6__ND__OPTION__DNSSL__STRUCT__FIXED,
            buffer,
            0,
            int(self.type),
            self.len >> 3,
            0,
            self.lifetime,
        )

        encoded = b"".join(_encode_domain(d) for d in self.domains)
        buffer[ICMP6__ND__OPTION__DNSSL__FIXED_LEN : ICMP6__ND__OPTION__DNSSL__FIXED_LEN + len(encoded)] = encoded
        # Trailing bytes are already zero from the bytearray
        # initialiser, satisfying the 8-octet padding rule.

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND DNSSL option before parsing it.
        """

        encoded_len = buffer[1] << 3
        if encoded_len < ICMP6__ND__OPTION__DNSSL__FIXED_LEN:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND DNSSL option length value must be at least "
                f"{ICMP6__ND__OPTION__DNSSL__FIXED_LEN} bytes. Got: {encoded_len!r}"
            )

        if encoded_len > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND DNSSL option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {encoded_len!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND DNSSL option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND DNSSL option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.DNSSL), (
            f"The ICMPv6 ND DNSSL option type must be {Icmp6NdOptionType.DNSSL!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        _type, length_units, _reserved, lifetime = struct.unpack(
            ICMP6__ND__OPTION__DNSSL__STRUCT__FIXED,
            buffer[:ICMP6__ND__OPTION__DNSSL__FIXED_LEN],
        )
        encoded_len = length_units << 3
        domains = _decode_domains(buffer[ICMP6__ND__OPTION__DNSSL__FIXED_LEN:encoded_len])

        return cls(
            lifetime=lifetime,
            domains=domains,
        )
