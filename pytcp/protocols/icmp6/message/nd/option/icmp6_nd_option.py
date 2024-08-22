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
This module contains the ICMPv6 ND option support code.

pytcp/protocols/icmp6/message/nd/option/icmp6_nd_option.py

ver 3.0.1
"""


from __future__ import annotations

from dataclasses import dataclass

from pytcp.lib.proto_option import ProtoOption, ProtoOptionType

ICMP6__ND_OPTION__STRUCT = "! BB"
ICMP6__ND_OPTION__LEN = 2


class Icmp6NdOptionType(ProtoOptionType):
    """
    The ICMPv6 ND option 'type' values.
    """

    SLLA = 1
    TLLA = 2
    PI = 3


@dataclass(frozen=True, kw_only=True)
class Icmp6NdOption(ProtoOption):
    """
    ICMPv6 ND option.
    """
