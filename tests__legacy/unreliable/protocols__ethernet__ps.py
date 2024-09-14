#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/ehternet_ps.py -  Tests specific for Ethernet PS module.
#
# ver 3.0.2
#

from testslide import TestCase

from net_addr import MacAddress
from protocols.ethernet.base import ETHERNET_HEADER_LEN, Ethernet, EthernetType
from pytcp.protocols.raw.raw__assembler import RawAssembler

ETHERNET__DST = MacAddress("00:11:22:33:44:55")
ETHERNET__SRC = MacAddress("66:77:88:99:AA:BB")
ETHERNET__TYPE = EthernetType.RAW
ETHERNET__CARRIED_PACKET = RawAssembler()
ETHERNET__TEST_FRAME = (
    b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xFF\xFF"
)


class TestEthernet(TestCase):
    """
    Ethernet Assembler unit test class.
    """

    class _Ethernet(Ethernet):
        def __init__(self) -> None:
            self._dst = ETHERNET__DST
            self._src = ETHERNET__SRC
            self._type = ETHERNET__TYPE

        def __len__(self) -> int:
            return ETHERNET_HEADER_LEN

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._packet = self._Ethernet()

        self._ethernet__dst = ETHERNET__DST
        self._ethernet__src = ETHERNET__SRC
        self._ethernet__type = ETHERNET__TYPE
        self._ethernet__test_frame = ETHERNET__TEST_FRAME

    def test__ethernet_ps____str__(self) -> None:
        """
        Verify that the '__str__()' dunder generates valid log string.
        """

        self.assertEqual(
            str(self._packet),
            f"ETHER {self._ethernet__src} > {self._ethernet__dst}, "
            f"0x{int(self._ethernet__type):0>4x} ({self._ethernet__type}), "
            f"plen {len(self._packet)}",
        )

    def test__ethernet_ps____repr__(self) -> None:
        """
        Verify that the '__repr__()' dunder generates valid representation string.
        """

        self.assertEqual(
            repr(self._packet),
            "Ethernet("
            f"src={self._ethernet__src!r}, "
            f"dst={self._ethernet__dst!r}, "
            f"type={self._ethernet__type!r})",
        )

    def test__ethernet_ps____bytes__(self) -> None:
        """
        Verify that the '__bytes__()' dunder generates valid raw packet.
        """

        self.assertEqual(bytes(self._packet), self._ethernet__test_frame)

    def test__ethernet_ps__getter__dst(self) -> None:
        """
        Validate that the '_dst' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.dst, self._ethernet__dst)

    def test__ethernet_ps__getter__src(self) -> None:
        """
        Validate that the '_src' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.src, self._ethernet__src)

    def test__ethernet_ps__getter__type(self) -> None:
        """
        Validate that the '_type' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.type, self._ethernet__type)
