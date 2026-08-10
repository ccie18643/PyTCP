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
This module contains the IPv6 Routing Header protocol error classes.

net_proto/protocols/ip6_routing/ip6_routing__errors.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError


class Ip6RoutingIntegrityError(PacketIntegrityError):
    """
    Exception raised when IPv6 Routing Header integrity check fails.

    Carries an optional 'pointer' field — the byte offset within the
    Routing Header that caused the problem. The chain-walker dispatch
    in the IPv6 RX path (Phase 8) translates this offset to the
    absolute IPv6-packet pointer (40 + offset_in_chain + pointer)
    and emits ICMPv6 Parameter Problem code 0 (erroneous header
    field encountered) per RFC 5095 §3 / RFC 8200 §4.4.
    """

    pointer: int | None

    @override
    def __init__(self, message: str, /, *, pointer: int | None = None) -> None:
        super().__init__("[IPv6 Routing] " + message)
        self.pointer = pointer


class Ip6RoutingSanityError(PacketSanityError):
    """
    Exception raised when IPv6 Routing Header sanity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[IPv6 Routing] " + message)
