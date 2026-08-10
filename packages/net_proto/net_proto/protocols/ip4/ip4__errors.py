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
This module contains the IPv4 protocol error classes.

net_proto/protocols/ip4/ip4__errors.py

ver 3.0.9
"""

from typing import override

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError


class Ip4IntegrityError(PacketIntegrityError):
    """
    Exception raised when IPv4 packet integrity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[IPv4] " + message)


class Ip4SanityError(PacketSanityError):
    """
    Exception raised when IPv4 packet sanity check fails.

    Carries an optional 'pointer' field — the byte offset of the
    offending header field, used by the packet handler when emitting
    an ICMPv4 Parameter Problem (Code 0) per RFC 1122 §3.2.2.5 / RFC
    792.
    """

    pointer: int | None

    @override
    def __init__(self, message: str, /, *, pointer: int | None = None) -> None:
        super().__init__("[IPv4] " + message)
        self.pointer = pointer
