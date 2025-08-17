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
Module contains the DHCPv4 option base class.

pytcp/protocols/tcp/options/dhcp_option.py

ver 3.0.2
"""


from __future__ import annotations

from dataclasses import dataclass

from pytcp.lib.proto_option import ProtoOption, ProtoOptionType

DHCP4__OPTION__STRUCT = "! BB"
DHCP4__OPTION__LEN = 2


class Dhcp4OptionType(ProtoOptionType):
    """
    DHCPv4 option types.
    """

    PAD = 0
    MESSAGE_TYPE = 53
    END = 255


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Option(ProtoOption):
    """
    The DHCPv4 option support class.
    """
