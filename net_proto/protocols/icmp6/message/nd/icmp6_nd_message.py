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
This module contains the ICMPv6 ND (Neighbor Discovery) messages support class.

net_proto/protocols/icmp6/message/nd/icmp6_nd_message.py

ver 3.0.4
"""


from dataclasses import dataclass

from net_addr import MacAddress
from net_proto.protocols.icmp6.message.icmp6_message import (
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
    NdPrefixInfo,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdMessage(Icmp6Message):
    """
    The ICMPv6 ND (Neighbor Discovery) message base.
    """

    type: Icmp6Type
    options: Icmp6NdOptions

    @property
    def option_slla(self) -> MacAddress | None:
        """
        Get the value of the ICMPv6 ND Slla option if present.
        """

        return self.options.slla

    @property
    def option_tlla(self) -> MacAddress | None:
        """
        Get the value of the ICMPv6 ND Tlla option if present.
        """

        return self.options.tlla

    @property
    def option_pi(self) -> list[NdPrefixInfo]:
        """
        Get the value of the ICMPv6 ND Pi option if present.
        """

        return self.options.pi
