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
Module contains the TCP option base class.

pytcp/protocols/tcp/options/tcp_option.py

ver 3.0.1
"""


from __future__ import annotations

from dataclasses import dataclass

from pytcp.lib.proto_option import ProtoOption, ProtoOptionType

TCP__OPTION__STRUCT = "! BB"
TCP__OPTION__LEN = 2


class TcpOptionType(ProtoOptionType):
    """
    TCP option types.
    """

    EOL = 0
    NOP = 1
    MSS = 2
    WSCALE = 3
    SACKPERM = 4
    SACK = 5
    TIMESTAMPS = 8


@dataclass(frozen=True, kw_only=True)
class TcpOption(ProtoOption):
    """
    The TCP option support class.
    """
