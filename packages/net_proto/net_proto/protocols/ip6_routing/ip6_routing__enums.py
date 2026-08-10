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
This module contains the IPv6 Routing Header enums.

net_proto/protocols/ip6_routing/ip6_routing__enums.py

ver 3.0.9
"""

from typing import override

from net_proto.lib.proto_enum import ProtoEnumByte


class Ip6RoutingType(ProtoEnumByte):
    """
    The IPv6 Routing Header 'routing_type' field values.
    """

    RH0 = 0  # DEPRECATED — RFC 5095 §3 mandates hard-drop on receipt.
    RH2 = 2  # Mobility (RFC 6275) — parsed as opaque, no semantic action.
    RH3 = 3  # RPL (RFC 6554) — parsed as opaque, no semantic action.
    RH4 = 4  # Segment Routing (RFC 8754) — parsed as opaque, no semantic action.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Ip6RoutingType.RH0:
                name = "RH0"
            case Ip6RoutingType.RH2:
                name = "RH2"
            case Ip6RoutingType.RH3:
                name = "RH3"
            case Ip6RoutingType.RH4:
                name = "RH4"
            case _:
                name = f"{self.value}"

        return name
