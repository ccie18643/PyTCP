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
This module contains the ICMPv6 ND Router Solicitation message support class.

net_proto/protocols/icmp6/message/nd/icmp6__nd__message__router_solicitation.py

ver 3.0.8
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

# The ICMPv6 ND Router Solicitation message (133/0) [RFC 4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Reserved                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                            Options                            ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__ROUTER_SOLICITATION__LEN = 8
ICMP6__ND__ROUTER_SOLICITATION__STRUCT = "! BBH L"


class Icmp6NdRouterSolicitationCode(Icmp6Code):
    """
    The ICMPv6 ND Router Solicitation 'code' field values.
    """

    DEFAULT = 0  # RFC 4861 §4.1: only code 0 defined.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdMessageRouterSolicitation(Icmp6NdMessage):
    """
    The ICMPv6 ND Router Solicitation message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.ND__ROUTER_SOLICITATION,
    )
    code: Icmp6NdRouterSolicitationCode = Icmp6NdRouterSolicitationCode.DEFAULT
    cksum: int = 0

    options: Icmp6NdOptions

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Router Solicitation message fields.
        """

        assert isinstance(
            self.code, Icmp6NdRouterSolicitationCode
        ), f"The 'code' field must be an Icmp6NdRouterSolicitationCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.options, Icmp6NdOptions
        ), f"The 'options' field must be an Icmp6NdOptions. Got: {type(self.options)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 ND Router Solicitation message length.
        """

        return ICMP6__ND__ROUTER_SOLICITATION__LEN + len(self.options)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Router Solicitation message log string.
        """

        return (
            f"ICMPv6 ND Router Solicitation, "
            f"{f'opts [{self.options}], ' if self.options else ''}"
            f"len {len(self)} ({ICMP6__ND__ROUTER_SOLICITATION__LEN}+"
            f"{len(self.options)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Router Solicitation message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP6__ND__ROUTER_SOLICITATION__LEN:] = bytearray(self.options)

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__ND__ROUTER_SOLICITATION__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 ND Router Solicitation message as bytes.
        """

        struct.pack_into(
            ICMP6__ND__ROUTER_SOLICITATION__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            0,
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 ND Router Solicitation message after parsing it.
        """

        # RFC 4861 §4.1 — the Router Solicitation 'Code' field is 0.
        if self.code.is_unknown:
            raise Icmp6SanityError(
                f"The 'code' field of the ICMPv6 ND Router Solicitation message "
                f"must be one of {Icmp6NdRouterSolicitationCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

        if ip6__hop != 255:
            raise Icmp6SanityError(
                f"ND Router Solicitation - [RFC 4861] The 'ip6__hop' field must be 255. Got: {ip6__hop!r}",
            )

        if not (ip6__src.is_unicast or ip6__src.is_unspecified):
            raise Icmp6SanityError(
                "ND Router Solicitation - [RFC 4861] The 'ip6__src' address "
                f"must be unicast or unspecified. Got: {ip6__src!r}",
            )

        if not ip6__dst.is_multicast__all_routers:
            raise Icmp6SanityError(
                "ND Router Solicitation - [RFC 4861] The 'ip6__dst' address "
                f"must be all-routers multicast. Got: {ip6__dst!r}",
            )

        if ip6__src.is_unspecified and self.slla is not None:
            raise Icmp6SanityError(
                "ND Router Solicitation - [RFC 4861] When the 'ip6__src' is unspecified, "
                f"the 'slla' option must not be included. Got: {self.slla!r}",
            )

        # RFC 4861 §6.1.1: the receiver-side option-presence MUSTs are
        # fully enforced — every option has length > 0
        # ('Icmp6NdOptions.validate_integrity') and, above, the
        # unspecified-source => no-SLLA rule. Options not specified for
        # Router Solicitation "MUST be ignored and the packet processed
        # as normal", so no further presence check is added here.

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 ND Router Solicitation message before parsing it.
        """

        if not (ICMP6__ND__ROUTER_SOLICITATION__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__ND__ROUTER_SOLICITATION__LEN <= ip6__dlen "
                f"<= len(frame)' must be met. Got: {ICMP6__ND__ROUTER_SOLICITATION__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

        Icmp6NdOptions.validate_integrity(
            frame=frame,
            offset=ICMP6__ND__ROUTER_SOLICITATION__LEN,
        )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Router Solicitation message from buffer.
        """

        type_, code, cksum, _ = struct.unpack(
            ICMP6__ND__ROUTER_SOLICITATION__STRUCT,
            buffer[:ICMP6__ND__ROUTER_SOLICITATION__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.ND__ROUTER_SOLICITATION
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6NdRouterSolicitationCode.from_int(code),
            cksum=cksum,
            options=Icmp6NdOptions.from_buffer(buffer[ICMP6__ND__ROUTER_SOLICITATION__LEN:]),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 ND Router Solicitation message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(bytearray(self.options))
