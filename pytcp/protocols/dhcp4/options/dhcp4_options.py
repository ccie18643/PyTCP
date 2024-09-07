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
Module contains the DHCPv4 packet options class.

pytcp/protocols/dhcp4/options/dhcp4_options.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import override

from pytcp.config import IP4__MIN_MTU
from pytcp.lib.proto_option import ProtoOptions
from pytcp.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from pytcp.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__LEN
from pytcp.protocols.dhcp4.options.dhcp4_option import (
    Dhcp4Option,
    Dhcp4OptionType,
)
from pytcp.protocols.dhcp4.options.dhcp4_option__end import Dhcp4OptionEnd
from pytcp.protocols.dhcp4.options.dhcp4_option__pad import (
    DHCP4__OPTION_PAD__LEN,
    Dhcp4OptionPad,
)
from pytcp.protocols.dhcp4.options.dhcp4_option__unknown import (
    Dhcp4OptionUnknown,
)
from pytcp.protocols.ip4.ip4__header import IP4__HEADER__LEN
from pytcp.protocols.udp.udp__header import UDP__HEADER__LEN

DHCP4__OPTIONS__MAX_LEN = (
    IP4__MIN_MTU - IP4__HEADER__LEN - UDP__HEADER__LEN - DHCP4__HEADER__LEN
)


class Dhcp4Options(ProtoOptions):
    """
    The DHCPv4 packet options.
    """

    @staticmethod
    def validate_integrity(
        *,
        frame: bytes,
        hlen: int,
    ) -> None:
        """
        Run the DHCPv4 options integrity checks before parsing options.
        """

        offset = DHCP4__HEADER__LEN

        while offset < hlen:
            if frame[offset] == int(Dhcp4OptionType.END):
                break

            if frame[offset] == int(Dhcp4OptionType.PAD):
                offset += DHCP4__OPTION_PAD__LEN
                continue

            if (value := frame[offset + 1]) < 2:
                raise Dhcp4IntegrityError(
                    f"The DHCPv4 option length must be greater than 1. "
                    f"Got: {value!r}.",
                )

            offset += frame[offset + 1]
            if offset > hlen:
                raise Dhcp4IntegrityError(
                    f"The DHCPv4 option length must not extend past the header "
                    f"length. Got: {offset=}, {hlen=}",
                )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> Dhcp4Options:
        """
        Read the DHCPv4 options from bytes.
        """

        offset = 0
        options: list[Dhcp4Option] = []

        while offset < len(_bytes):
            match Dhcp4OptionType.from_bytes(_bytes[offset:]):
                case Dhcp4OptionType.END:
                    options.append(Dhcp4OptionEnd.from_bytes(_bytes[offset:]))
                    break
                case Dhcp4OptionType.PAD:
                    options.append(Dhcp4OptionPad.from_bytes(_bytes[offset:]))
                case _:
                    options.append(
                        Dhcp4OptionUnknown.from_bytes(_bytes[offset:])
                    )

            offset += options[-1].len

        return Dhcp4Options(*options)


class Dhcp4OptionsProperties(ABC):
    """
    The DHCPv4 options properties mixin class.
    """

    _options: Dhcp4Options
