#!/usr/bin/env python3

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
Module contains ICMPv6 Neighbor Discovery option support classes.

pytcp/protocols/icmp6/message/nd/option/icmp6_nd_options.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from net_addr import MacAddress
from pytcp.lib.proto_option import ProtoOptions
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    Icmp6NdOption,
    Icmp6NdOptionType,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__pi import (
    Icmp6NdOptionPi,
    NdPrefixInfo,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__slla import (
    Icmp6NdOptionSlla,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__tlla import (
    Icmp6NdOptionTlla,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__unknown import (
    Icmp6NdOptionUnknown,
)


class Icmp6NdOptions(ProtoOptions):
    """
    The ICMPv6 ND message options.
    """

    @property
    def slla(self) -> MacAddress | None:
        """
        Get the value of the ICMPv6 ND Slla option if present.
        """

        for option in self._options:
            if isinstance(option, Icmp6NdOptionSlla):
                return option.slla

        return None

    @property
    def tlla(self) -> MacAddress | None:
        """
        Get the value of the ICMPv6 ND Tlla option if present.
        """

        for option in self._options:
            if isinstance(option, Icmp6NdOptionTlla):
                return option.tlla

        return None

    @property
    def pi(self) -> list[NdPrefixInfo]:
        """
        Get the value of the ICMPv6 ND Pi option if present.
        """

        prefix_info_list = []

        for option in self._options:
            if isinstance(option, Icmp6NdOptionPi):
                prefix_info_list.append(
                    NdPrefixInfo(
                        flag_l=option.flag_l,
                        flag_a=option.flag_a,
                        flag_r=option.flag_r,
                        valid_lifetime=option.valid_lifetime,
                        preferred_lifetime=option.preferred_lifetime,
                        prefix=option.prefix,
                    )
                )

        return prefix_info_list

    @staticmethod
    def validate_integrity(
        *,
        frame: bytes,
        offset: int,
    ) -> None:
        """
        Run the IPv4 options integrity checks before parsing options.
        """

        plen = len(frame)

        while offset < plen:
            if (value := frame[offset + 1] << 3) < 8:
                raise Icmp6IntegrityError(
                    f"The ICMPv6 ND option length must be greater than or equal to 8."
                    f"Got: {value!r}.",
                )

            offset += frame[offset + 1] << 3
            if offset > plen:
                raise Icmp6IntegrityError(
                    f"The ICMPv6 ND option length must not extend past the header "
                    f"length. Got: {offset=}, {plen=}",
                )

    @override
    @staticmethod
    def from_bytes(bytes: bytes, /) -> Icmp6NdOptions:
        """
        Read the ICMPv6 ND options from bytes.
        """

        offset = 0
        options: list[Icmp6NdOption] = []

        while offset < len(bytes):
            match Icmp6NdOptionType.from_bytes(bytes[offset:]):
                case Icmp6NdOptionType.SLLA:
                    options.append(Icmp6NdOptionSlla.from_bytes(bytes[offset:]))
                case Icmp6NdOptionType.TLLA:
                    options.append(Icmp6NdOptionTlla.from_bytes(bytes[offset:]))
                case Icmp6NdOptionType.PI:
                    options.append(Icmp6NdOptionPi.from_bytes(bytes[offset:]))
                case _:
                    options.append(
                        Icmp6NdOptionUnknown.from_bytes(bytes[offset:])
                    )

            offset += options[-1].len

        return Icmp6NdOptions(*options)
