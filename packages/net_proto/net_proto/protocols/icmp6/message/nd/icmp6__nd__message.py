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
This module contains the ICMPv6 ND (Neighbor Discovery) message base class.

net_proto/protocols/icmp6/message/nd/icmp6__nd__message.py

ver 3.0.9
"""

from dataclasses import dataclass

from net_addr import MacAddress
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__pi import (
    NdPrefixInfo,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__options import (
    Icmp6NdOptions,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdMessage(Icmp6Message):
    """
    The ICMPv6 ND (Neighbor Discovery) message base.
    """

    type: Icmp6Type
    options: Icmp6NdOptions

    @property
    def slla(self) -> MacAddress | None:
        """
        Get the value of the ICMPv6 ND Slla option if present.
        """

        return self.options.slla

    @property
    def tlla(self) -> MacAddress | None:
        """
        Get the value of the ICMPv6 ND Tlla option if present.
        """

        return self.options.tlla

    @property
    def pi(self) -> list[NdPrefixInfo]:
        """
        Get the prefix info entries from every ICMPv6 ND Pi option
        present, returning an empty list if none are present.
        """

        return self.options.pi

    @property
    def nonce(self) -> bytes | None:
        """
        Get the value of the ICMPv6 ND Nonce option if present
        (RFC 3971 §5.3.2 / RFC 7527 §4.1).
        """

        return self.options.nonce
