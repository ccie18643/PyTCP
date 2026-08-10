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
This module contains the DHCPv4 protocol base class.

net_proto/protocols/dhcp4/dhcp4__base.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.proto import Proto
from net_proto.protocols.dhcp4.dhcp4__header import (
    Dhcp4Header,
    Dhcp4HeaderProperties,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import (
    Dhcp4Options,
    Dhcp4OptionsProperties,
)


class Dhcp4(Proto, Dhcp4HeaderProperties, Dhcp4OptionsProperties):
    """
    The DHCPv4 protocol base.
    """

    _header: Dhcp4Header
    _options: Dhcp4Options

    @override
    def __len__(self) -> int:
        """
        Get the DHCPv4 packet length.
        """

        return len(self._header) + len(self._options)

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 packet log string.
        """

        return (
            f"DHCPv4 {self._header.operation}, xid {self._header.xid}, "
            f"ciaddr {self._header.ciaddr}, yiaddr {self._header.yiaddr}, "
            f"giaddr {self._header.giaddr}, chaddr {self._header.chaddr}"
            f"{f', opts [{self._options}]' if self._options else ''}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the DHCPv4 packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, options={self._options!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 packet as a memoryview.
        """

        buffer = bytearray(self._header)
        buffer += bytearray(self._options)

        return memoryview(buffer)

    @property
    def header(self) -> Dhcp4Header:
        """
        Get the DHCPv4 packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> Dhcp4Options:
        """
        Get the DHCPv4 packet '_options' attribute.
        """

        return self._options
