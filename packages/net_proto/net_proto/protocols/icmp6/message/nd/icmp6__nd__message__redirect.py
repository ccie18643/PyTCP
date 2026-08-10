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
This module contains the ICMPv6 ND Redirect message support class.

net_proto/protocols/icmp6/message/nd/icmp6__nd__message__redirect.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp6.icmp6__errors import (
    Icmp6IntegrityError,
    Icmp6SanityError,
)
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Code,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message import (
    Icmp6NdMessage,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__options import (
    Icmp6NdOptions,
)

# The ICMPv6 ND Redirect message (137/0) [RFC 4861 §4.5].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                     Destination Address                       +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                          Options                              ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__REDIRECT__LEN = 40
ICMP6__ND__REDIRECT__STRUCT = "! BBH L 16s 16s"


class Icmp6NdRedirectCode(Icmp6Code):
    """
    The ICMPv6 ND Redirect 'code' field values.
    """

    DEFAULT = 0  # RFC 4861 §4.5: only code 0 defined.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdMessageRedirect(Icmp6NdMessage):
    """
    The ICMPv6 ND Redirect message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.ND__REDIRECT,
    )
    code: Icmp6NdRedirectCode = Icmp6NdRedirectCode.DEFAULT
    cksum: int = 0

    target_address: Ip6Address
    destination_address: Ip6Address
    options: Icmp6NdOptions

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Redirect message fields.
        """

        assert isinstance(
            self.code, Icmp6NdRedirectCode
        ), f"The 'code' field must be an Icmp6NdRedirectCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.target_address, Ip6Address
        ), f"The 'target_address' field must be an Ip6Address. Got: {type(self.target_address)!r}"

        assert isinstance(
            self.destination_address, Ip6Address
        ), f"The 'destination_address' field must be an Ip6Address. Got: {type(self.destination_address)!r}"

        assert isinstance(
            self.options, Icmp6NdOptions
        ), f"The 'options' field must be an Icmp6NdOptions. Got: {type(self.options)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 ND Redirect message length.
        """

        return ICMP6__ND__REDIRECT__LEN + len(self.options)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Redirect message log string.
        """

        return (
            f"ICMPv6 ND Redirect, target {self.target_address}, "
            f"destination {self.destination_address}, "
            f"{f'opts [{self.options}], ' if self.options else ''}"
            f"len {len(self)} ({ICMP6__ND__REDIRECT__LEN}+"
            f"{len(self.options)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Redirect message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP6__ND__REDIRECT__LEN:] = bytearray(self.options)

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__ND__REDIRECT__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 ND Redirect message header as bytes.
        """

        struct.pack_into(
            ICMP6__ND__REDIRECT__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            0,
            bytes(self.target_address),
            bytes(self.destination_address),
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 ND Redirect message after parsing it.
        Implements the parse-time RFC 4861 §8.1 acceptance gates:
        Hop Limit MUST be 255, IP Source Address MUST be the link-
        local address of the redirecting router, and the ICMP
        Destination Address field MUST NOT be a multicast address.
        Runtime gates that need stack state (sender-is-first-hop-
        router, accept_redirects sysctl, target acceptability) are
        enforced at the RX-handler level.
        """

        # RFC 4861 §4.5 — the Redirect 'Code' field is 0.
        if self.code.is_unknown:
            raise Icmp6SanityError(
                f"The 'code' field of the ICMPv6 ND Redirect message "
                f"must be one of {Icmp6NdRedirectCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

        if ip6__hop != 255:
            raise Icmp6SanityError(
                f"ND Redirect - [RFC 4861] The 'ip6__hop' field must be 255. Got: {ip6__hop!r}",
            )

        if not ip6__src.is_link_local:
            raise Icmp6SanityError(
                f"ND Redirect - [RFC 4861] The 'ip6__src' address must be link-local. Got: {ip6__src!r}",
            )

        if self.destination_address.is_multicast:
            raise Icmp6SanityError(
                "ND Redirect - [RFC 4861] The 'destination_address' field must not "
                f"be multicast. Got: {self.destination_address!r}",
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 ND Redirect message before parsing it.
        """

        if not (ICMP6__ND__REDIRECT__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__ND__REDIRECT__LEN <= ip6__dlen <= len(frame)' must be met. "
                f"Got: {ICMP6__ND__REDIRECT__LEN=}, {ip6__dlen=}, {len(frame)=}"
            )

        Icmp6NdOptions.validate_integrity(
            frame=frame,
            offset=ICMP6__ND__REDIRECT__LEN,
        )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Redirect message from buffer.
        """

        type_, code, cksum, _reserved, target, destination = struct.unpack(
            ICMP6__ND__REDIRECT__STRUCT,
            buffer[:ICMP6__ND__REDIRECT__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.ND__REDIRECT
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6NdRedirectCode.from_int(code),
            cksum=cksum,
            target_address=Ip6Address(target),
            destination_address=Ip6Address(destination),
            options=Icmp6NdOptions.from_buffer(buffer[ICMP6__ND__REDIRECT__LEN:]),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 ND Redirect message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(bytearray(self.options))
