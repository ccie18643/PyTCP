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
Package contains classes used to represent network addresses.

pytcp/lib/net_addr/__init__.py

ver 3.0.2
"""


from .click_types import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp4Mask,
    ClickTypeIp4Network,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeIp6Mask,
    ClickTypeIp6Network,
    ClickTypeMacAddress,
)
from .errors import (
    Ip4AddressFormatError,
    Ip4HostFormatError,
    Ip4HostGatewayError,
    Ip4HostSanityError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
    Ip6AddressFormatError,
    Ip6HostFormatError,
    Ip6HostGatewayError,
    Ip6HostSanityError,
    Ip6MaskFormatError,
    Ip6NetworkFormatError,
    IpAddressFormatError,
    IpHostFormatError,
    IpHostGatewayError,
    IpMaskFormatError,
    IpNetworkFormatError,
    MacAddressFormatError,
)
from .ip4_address import IP4__ADDRESS_LEN, Ip4Address
from .ip4_host import Ip4Host, Ip4HostOrigin
from .ip4_mask import Ip4Mask
from .ip4_network import Ip4Network
from .ip6_address import IP6__ADDRESS_LEN, Ip6Address
from .ip6_host import Ip6Host, Ip6HostOrigin
from .ip6_mask import Ip6Mask
from .ip6_network import Ip6Network
from .ip_address import IpAddress
from .mac_address import MacAddress
