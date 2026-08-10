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
This module contains the ICMPv6 ND Router Advertisement message support class.

net_proto/protocols/icmp6/message/nd/icmp6__nd__message__router_advertisement.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint8, is_uint16, is_uint32
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
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__route_info import (
    Icmp6NdRoutePreference,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__options import (
    Icmp6NdOptions,
)

# The ICMPv6 ND Router Advertisement message (134/0) [RFC 4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Hop Limit   |M|O|H|PRF|P|0|0|        Router Lifetime        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Reachable Time                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Retrans Timer                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                            Options                            ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__ROUTER_ADVERTISEMENT__LEN = 16
ICMP6__ND__ROUTER_ADVERTISEMENT__STRUCT = "! BBH BBH L L"


class Icmp6NdRouterAdvertisementCode(Icmp6Code):
    """
    The ICMPv6 ND Router Advertisement 'code' field values.
    """

    DEFAULT = 0  # RFC 4861 §4.2: only code 0 defined.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdMessageRouterAdvertisement(Icmp6NdMessage):
    """
    The ICMPv6 ND Router Advertisement message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.ND__ROUTER_ADVERTISEMENT,
    )
    code: Icmp6NdRouterAdvertisementCode = Icmp6NdRouterAdvertisementCode.DEFAULT
    cksum: int = 0

    hop: int
    flag_m: bool = False
    flag_o: bool = False
    prf: Icmp6NdRoutePreference = Icmp6NdRoutePreference.MEDIUM
    router_lifetime: int
    reachable_time: int
    retrans_timer: int
    options: Icmp6NdOptions

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Router Advertisement message fields.
        """

        assert isinstance(
            self.code, Icmp6NdRouterAdvertisementCode
        ), f"The 'code' field must be an Icmp6NdRouterAdvertisementCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert is_uint8(self.hop), f"The 'hop' field must be an 8-bit unsigned integer. Got: {self.hop!r}"

        assert isinstance(self.flag_m, bool), f"The 'flag_m' field must be a boolean. Got: {type(self.flag_m)!r}"

        assert isinstance(self.flag_o, bool), f"The 'flag_o' field must be a boolean. Got: {type(self.flag_o)!r}"

        assert isinstance(
            self.prf, Icmp6NdRoutePreference
        ), f"The 'prf' field must be an Icmp6NdRoutePreference. Got: {type(self.prf)!r}"

        assert is_uint16(
            self.router_lifetime
        ), f"The 'router_lifetime' field must be a 16-bit unsigned integer. Got: {self.router_lifetime!r}"

        assert is_uint32(
            self.reachable_time
        ), f"The 'reachable_time' field must be a 32-bit unsigned integer. Got: {self.reachable_time!r}"

        assert is_uint32(
            self.retrans_timer
        ), f"The 'retrans_timer' field must be a 32-bit unsigned integer. Got: {self.retrans_timer!r}"

        assert isinstance(
            self.options, Icmp6NdOptions
        ), f"The 'options' field must be an Icmp6NdOptions. Got: {type(self.options)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 ND Router Advertisement message length.
        """

        return ICMP6__ND__ROUTER_ADVERTISEMENT__LEN + len(self.options)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Router Advertisement message log string.
        """

        return (
            f"ICMPv6 ND Router Advertisement, hop {self.hop}, flags "
            f"{'M' if self.flag_m else '-'}{'O' if self.flag_o else '-'}, "
            f"rlft {self.router_lifetime}, reacht {self.reachable_time}, "
            f"retrt {self.retrans_timer}, "
            f"{f'opts [{self.options}], ' if self.options else ''}"
            f"len {len(self)} ({ICMP6__ND__ROUTER_ADVERTISEMENT__LEN}+"
            f"{len(self.options)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Router Advertisement message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP6__ND__ROUTER_ADVERTISEMENT__LEN:] = bytearray(self.options)

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__ND__ROUTER_ADVERTISEMENT__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 ND Router Advertisement message as bytes.
        """

        struct.pack_into(
            ICMP6__ND__ROUTER_ADVERTISEMENT__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            self.hop,
            (self.flag_m << 7) | (self.flag_o << 6) | (int(self.prf) << 3),
            self.router_lifetime,
            self.reachable_time,
            self.retrans_timer,
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 ND Router Advertisement message after parsing it.
        """

        # RFC 4861 §4.2 — the Router Advertisement 'Code' field is 0.
        if self.code.is_unknown:
            raise Icmp6SanityError(
                f"The 'code' field of the ICMPv6 ND Router Advertisement message "
                f"must be one of {Icmp6NdRouterAdvertisementCode.get_known_values()}. "
                f"Got: {int(self.code)}."
            )

        if ip6__hop != 255:
            raise Icmp6SanityError(
                f"ND Router Advertisement - [RFC 4861] The 'ip6__hop' field must be 255. Got: {ip6__hop!r}",
            )

        if not ip6__src.is_link_local:
            raise Icmp6SanityError(
                "ND Router Advertisement - [RFC 4861] The 'ip6__src' address " f"must be link-local. Got: {ip6__src!r}",
            )

        if not (ip6__dst.is_unicast or ip6__dst.is_multicast__all_nodes):
            raise Icmp6SanityError(
                "ND Router Advertisement - [RFC 4861] The 'ip6__dst' address "
                f"must be unicast or all-nodes multicast. Got: {ip6__dst!r}",
            )

        # RFC 4861 §6.1.2: the only receiver-side option-presence MUST is
        # that every included option has length > 0, enforced in
        # 'Icmp6NdOptions.validate_integrity'. Options not specified for
        # Router Advertisement "MUST be ignored and the packet processed
        # as normal", so no further presence check is added here.

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 ND Router Advertisement message before parsing it.
        """

        if not (ICMP6__ND__ROUTER_ADVERTISEMENT__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__ND__ROUTER_ADVERTISEMENT__LEN <= ip6__dlen "
                f"<= len(frame)' must be met. Got: {ICMP6__ND__ROUTER_ADVERTISEMENT__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

        Icmp6NdOptions.validate_integrity(
            frame=frame,
            offset=ICMP6__ND__ROUTER_ADVERTISEMENT__LEN,
        )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Router Advertisement message from buffer.
        """

        (
            type_,
            code,
            cksum,
            hop,
            flags,
            router_lifetime,
            reachable_time,
            retrans_timer,
        ) = struct.unpack(
            ICMP6__ND__ROUTER_ADVERTISEMENT__STRUCT,
            buffer[:ICMP6__ND__ROUTER_ADVERTISEMENT__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.ND__ROUTER_ADVERTISEMENT
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return cls(
            code=Icmp6NdRouterAdvertisementCode.from_int(code),
            cksum=cksum,
            hop=hop,
            flag_m=bool(flags & 0b10000000),
            flag_o=bool(flags & 0b01000000),
            prf=Icmp6NdRoutePreference((flags >> 3) & 0b11),
            router_lifetime=router_lifetime,
            reachable_time=reachable_time,
            retrans_timer=retrans_timer,
            options=Icmp6NdOptions.from_buffer(buffer[ICMP6__ND__ROUTER_ADVERTISEMENT__LEN:]),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 ND Router Advertisement message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(bytearray(self.options))
