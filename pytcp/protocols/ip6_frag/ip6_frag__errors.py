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
This module contains the IPv6 Frag protocol error classes.

pytcp/protocols/ip6_frag/ip6_frag__errors.py

ver 3.0.3
"""


from pytcp.protocols.errors import PacketIntegrityError, PacketSanityError


class Ip6FragIntegrityError(PacketIntegrityError):
    """
    Exception raised when IPv6 Frag packet integrity check fails.
    """

    def __init__(self, message: str, /) -> None:
        super().__init__("[IPv6 Frag] " + message)


class Ip6FragSanityError(PacketSanityError):
    """
    Exception raised when IPv6 Frag packet sanity check fails.
    """

    def __init__(self, message: str, /) -> None:
        super().__init__("[IPv6 Frag] " + message)
