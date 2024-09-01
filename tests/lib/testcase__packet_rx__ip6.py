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
Module contains the customized TestCase class that mocks the IPv6 related values.

tests/mocks/testcase__packet_rx__ip6.py

ver 3.0.2
"""


from typing import Any, cast

from testslide import StrictMock, TestCase

from pytcp.lib.net_addr import Ip6Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6.ip6__parser import Ip6Parser


class TestCasePacketRxIp6(TestCase):
    """
    Customized TestCase class that provides PacketRx object and mocks the
    IPv6 parser values.
    """

    _args: dict[str, Any] = {}
    _mocked_values: dict[str, Any] = {}
    _packet_rx: PacketRx

    def setUp(self) -> None:
        """
        Set up the mocked values for the IPv6 related fields.
        """

        self._packet_rx = PacketRx(self._args["bytes"])

        self._packet_rx.ip = self._packet_rx.ip6 = cast(
            Ip6Parser, StrictMock(template=Ip6Parser)
        )
        self.patch_attribute(
            target=self._packet_rx.ip6,
            attribute="dlen",
            new_value=self._mocked_values.get(
                "ip6__dlen", len(self._args["bytes"])
            ),
        )
        self.patch_attribute(
            target=self._packet_rx.ip6,
            attribute="payload_len",
            new_value=self._mocked_values.get(
                "ip6__dlen", len(self._args["bytes"])
            ),
        )
        self.patch_attribute(
            target=self._packet_rx.ip6,
            attribute="pshdr_sum",
            new_value=self._mocked_values.get("ip6__pshdr_sum", 0),
        )
        self.patch_attribute(
            target=self._packet_rx.ip6,
            attribute="hop",
            new_value=self._mocked_values.get("ip6__hop", 0),
        )
        self.patch_attribute(
            target=self._packet_rx.ip6,
            attribute="src",
            new_value=self._mocked_values.get("ip6__src", Ip6Address()),
        )
        self.patch_attribute(
            target=self._packet_rx.ip6,
            attribute="dst",
            new_value=self._mocked_values.get("ip6__dst", Ip6Address()),
        )
