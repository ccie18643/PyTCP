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
Module contains the ICMPv4 protocol error classes.

pytcp/protocols/icmp4/icmp4__errors.py

ver 3.0.2
"""


from __future__ import annotations

from pytcp.lib.errors import PacketIntegrityError, PacketSanityError


class Icmp4IntegrityError(PacketIntegrityError):
    """
    The ICMPv4 packet integrity check failure.
    """

    def __init__(self, /, message: str):
        super().__init__("[ICMPv4] " + message)


class Icmp4SanityError(PacketSanityError):
    """
    The ICMPv4 packet sanity check failure.
    """

    def __init__(self, /, message: str):
        super().__init__("[ICMPv4] " + message)
