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
Module contains the customized TestCase class that mocks the IPv4 related values.

tests/mocks/testcase__packet_rx__ip4.py

ver 3.0.1
"""


from typing import Any, cast

from testslide import StrictMock, TestCase

from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__parser import Ip4Parser


class TestCasePacketRxIp4(TestCase):
    """
    Customized TestCase class that provides PacketRx object and mocks the
    IPv4 parser values.
    """

    _args: dict[str, Any] = {}
    _mocked_values: dict[str, Any] = {}
    _packet_rx: PacketRx

    def setUp(self) -> None:
        """
        Set up the mocked values for the IPv4 related fields.
        """

        self._packet_rx = PacketRx(self._args["bytes"])

        self._packet_rx.ip = self._packet_rx.ip4 = cast(
            Ip4Parser, StrictMock(template=Ip4Parser)
        )
        self.patch_attribute(
            target=self._packet_rx.ip4,
            attribute="payload_len",
            new_value=self._mocked_values.get(
                "ip4__payload_len", len(self._args["bytes"])
            ),
        )
        self.patch_attribute(
            target=self._packet_rx.ip4,
            attribute="pshdr_sum",
            new_value=self._mocked_values.get("ip4__pshdr_sum", 0),
        )
        self.patch_attribute(
            target=self._packet_rx.ip4,
            attribute="ttl",
            new_value=self._mocked_values.get("ip4__ttl", 0),
        )
        self.patch_attribute(
            target=self._packet_rx.ip4,
            attribute="src",
            new_value=self._mocked_values.get("ip4__src", Ip4Address()),
        )
        self.patch_attribute(
            target=self._packet_rx.ip4,
            attribute="dst",
            new_value=self._mocked_values.get("ip4__dst", Ip4Address()),
        )
