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
This module contains IP base class.

net_addr/ip.py

ver 3.0.4
"""


from abc import ABC

from net_addr.ip_version import IpVersion


class Ip(ABC):
    """
    IP support base class.
    """

    __slots__ = ()

    _version: IpVersion

    @property
    def version(self) -> IpVersion:
        """
        Get the IP object version.
        """

        return self._version

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP object version is 6.
        """

        return self._version == IpVersion.IP6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP object version is 4.
        """

        return self._version == IpVersion.IP4
