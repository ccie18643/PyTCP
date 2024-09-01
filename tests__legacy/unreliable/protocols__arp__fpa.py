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
# tests/unit/arp_fpa.py -  Tests specific for ARP FPA module.
#
# ver 3.0.2
#

from testslide import TestCase

from pytcp.lib.net_addr import Ip4Address
from pytcp.lib.net_addr import MacAddress
from pytcp.protocols.arp.fpa import ArpAssembler
from protocols.arp.base import ARP_HEADER_LEN, ArpOperation
from tests.unit.protocols__arp__ps import (
    ARP__HRLEN,
    ARP__HRTYPE,
    ARP__OPER,
    ARP__PRLEN,
    ARP__PRTYPE,
    ARP__SHA,
    ARP__SPA,
    ARP__TEST_FRAME,
    ARP__THA,
    ARP__TPA,
)


class TestArpAssembler(TestCase):
    """
    ARP Assembler unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._arp__hrtype = ARP__HRTYPE
        self._arp__prtype = ARP__PRTYPE
        self._arp__hrlen = ARP__HRLEN
        self._arp__prlen = ARP__PRLEN
        self._arp__oper = ARP__OPER
        self._arp__sha = ARP__SHA
        self._arp__spa = ARP__SPA
        self._arp__tha = ARP__THA
        self._arp__tpa = ARP__TPA
        self._arp__test_frame = ARP__TEST_FRAME

        self._packet = ArpAssembler(
            arp__oper=self._arp__oper,
            arp__sha=self._arp__sha,
            arp__spa=self._arp__spa,
            arp__tha=self._arp__tha,
            arp__tpa=self._arp__tpa,
        )

    def test__arp_fpa____init__(self) -> None:
        """
        Validate that the class constructor creates packet matching
        provided arguments.
        """

        self.assertIs(self._packet._hrtype, self._arp__hrtype)
        self.assertIs(self._packet._prtype, self._arp__prtype)
        self.assertIs(self._packet._hrlen, self._arp__hrlen)
        self.assertIs(self._packet._prlen, self._arp__prlen)
        self.assertIs(self._packet._oper, self._arp__oper)
        self.assertIs(self._packet._sha, self._arp__sha)
        self.assertIs(self._packet._spa, self._arp__spa)
        self.assertIs(self._packet._tha, self._arp__tha)
        self.assertIs(self._packet._tpa, self._arp__tpa)

    def test__arp_fpa____init____defaults(self) -> None:
        """
        Validate that the packet constructor has set specific default
        values.
        """

        default_packet = ArpAssembler()

        self.assertIs(default_packet._oper, ArpOperation.REQUEST)
        self.assertEqual(default_packet._sha, MacAddress("00:00:00:00:00:00"))
        self.assertEqual(default_packet._spa, Ip4Address("0.0.0.0"))
        self.assertEqual(default_packet._tha, MacAddress("00:00:00:00:00:00"))
        self.assertEqual(default_packet._tpa, Ip4Address("0.0.0.0"))

    def test__arp_fpa____len__(self) -> None:
        """
        Verify that the '__len__()' dunder provides valid packet length.
        """

        self.assertEqual(len(self._packet), ARP_HEADER_LEN)

    def test__arp_fpa__getter__tracker(self) -> None:
        """
        Validate that the '_tracker' attribute getter provides correct value.
        """

        self.assertRegex(
            repr(self._packet.tracker), r"^Tracker\(serial='<lr>TX"
        )

    def test__arp_fpa__assemble(self) -> None:
        """
        Validate that the 'assemble()' method correctly writes data into frame.
        """

        frame = memoryview(bytearray(len(self._packet)))
        self._packet.assemble(frame)

        self.assertEqual(bytes(frame), self._arp__test_frame)
