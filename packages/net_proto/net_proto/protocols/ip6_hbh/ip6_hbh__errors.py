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
This module contains the IPv6 Hop-by-Hop Options protocol error classes.

net_proto/protocols/ip6_hbh/ip6_hbh__errors.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError


class Ip6HbhIntegrityError(PacketIntegrityError):
    """
    Exception raised when IPv6 Hop-by-Hop Options packet integrity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[IPv6 HBH] " + message)


class Ip6HbhSanityError(PacketSanityError):
    """
    Exception raised when IPv6 Hop-by-Hop Options packet sanity check fails.

    Carries an optional 'pointer' field — the byte offset within the
    HBH options block of an option whose top-2-bit action-on-unrecognized
    code (RFC 8200 §4.2) requires the receiver to emit ICMPv6 Parameter
    Problem code 2 (unrecognized option). The chain-walker dispatch in
    the IPv6 RX path (Phase 8) consumes this pointer to build the ICMP
    response. 'None' means "discard silently, no ICMP".
    """

    pointer: int | None
    multicast_only: bool

    @override
    def __init__(
        self,
        message: str,
        /,
        *,
        pointer: int | None = None,
        multicast_only: bool = False,
    ) -> None:
        super().__init__("[IPv6 HBH] " + message)
        self.pointer = pointer
        self.multicast_only = multicast_only
