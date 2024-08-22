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
This module contains the IPv4 packet option classes.

pytcp/protocols/ip4/options/ip4_options.py

ver 3.0.1
"""


from __future__ import annotations

from abc import ABC
from typing import override

from pytcp.lib.proto_option import ProtoOptions
from pytcp.protocols.ip4.options.ip4_option import Ip4Option, Ip4OptionType
from pytcp.protocols.ip4.options.ip4_option__eol import Ip4OptionEol
from pytcp.protocols.ip4.options.ip4_option__nop import Ip4OptionNop
from pytcp.protocols.ip4.options.ip4_option__unknown import Ip4OptionUnknown

IP4__OPTIONS__MAX_LEN = 40


class Ip4Options(ProtoOptions):
    """
    The IPv4 packet options.
    """

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Ip4Options:
        """
        Read the IPv4 options from bytes.
        """

        offset = 0
        options: list[Ip4Option] = []

        while offset < len(_bytes):
            match Ip4OptionType.from_bytes(_bytes[offset:]):
                case Ip4OptionType.EOL:
                    options.append(Ip4OptionEol.from_bytes(_bytes[offset:]))
                    break
                case Ip4OptionType.NOP:
                    options.append(Ip4OptionNop.from_bytes(_bytes[offset:]))
                case _:
                    options.append(Ip4OptionUnknown.from_bytes(_bytes[offset:]))

            offset += options[-1].len

        return Ip4Options(*options)


class Ip4OptionsProperties(ABC):
    """
    The IPv4 options properties mixin class.
    """

    _options: Ip4Options
