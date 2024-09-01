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
# tests/unit/arp_ps.py -  Tests specific for ARP PS module.
#
# ver 3.0.2
#

from testslide import TestCase

from pytcp.lib.net_addr import Ip4Address
from pytcp.lib.net_addr import MacAddress
from protocols.arp.base import (
    Arp,
    ArpHardwareLength,
    ArpHardwareType,
    ArpOperation,
    ArpProtocolLength,
    ArpProtocolType,
)
from protocols.ethernet.base import EthernetType

ARP__HRTYPE = ArpHardwareType.ETHERNET
ARP__PRTYPE = ArpProtocolType.IP4
ARP__HRLEN = ArpHardwareLength.ETHERNET
ARP__PRLEN = ArpProtocolLength.IP4
ARP__OPER = ArpOperation.REQUEST
ARP__SHA = MacAddress("00:11:22:33:44:55")
ARP__SPA = Ip4Address("1.2.3.4")
ARP__THA = MacAddress("66:77:88:99:AA:BB")
ARP__TPA = Ip4Address("5.6.7.8")
ARP__TEST_FRAME = (
    b"\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11\x22\x33\x44\x55\x01\x02"
    b"\x03\x04\x66\x77\x88\x99\xAA\xBB\x05\x06\x07\x08"
)


class TestArp(TestCase):
    """
    ARP Assembler unit test class.
    """

    class _Arp(Arp):
        def __init__(self) -> None:
            self._hrtype = ARP__HRTYPE
            self._prtype = ARP__PRTYPE
            self._hrlen = ARP__HRLEN
            self._prlen = ARP__PRLEN
            self._oper = ARP__OPER
            self._sha = ARP__SHA
            self._spa = ARP__SPA
            self._tha = ARP__THA
            self._tpa = ARP__TPA

        def __len__(self) -> int:
            raise NotImplementedError

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._packet = self._Arp()

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

    def test__arp_fpa____str__(self) -> None:
        """
        Verify that the '__str__()' dunder generates valid log string.
        """

        self.assertEqual(
            str(self._packet),
            f"ARP {self._arp__oper} {self._arp__spa} / {self._arp__sha} "
            f"> {self._arp__tpa} / {self._arp__tha}",
        )

    def test__arp_ps____repr__(self) -> None:
        """
        Verify that the '__repr__()' dunder generates valid representation string.
        """

        self.assertEqual(
            repr(self._packet),
            "Arp("
            f"hrtype={self._arp__hrtype!r}, "
            f"prtype={self._arp__prtype!r}, "
            f"hrlen={self._arp__hrlen!r}, "
            f"prlen={self._arp__prlen!r}, "
            f"oper={self._arp__oper!r}, "
            f"sha={self._arp__sha!r}, "
            f"spa={self._arp__spa!r}, "
            f"tha={self._arp__tha!r}, "
            f"tpa={self._arp__tpa!r})",
        )

    def test__arp_ps____bytes__(self) -> None:
        """
        Verify that the '__bytes__()' dunder generates valid raw packet.
        """

        self.assertEqual(bytes(self._packet), self._arp__test_frame)

    def test__arp_ps__getter__ethernet_type(self) -> None:
        """
        Validate that the '_ethernet_type' attribute getter provides correct value.
        """

        self.assertIs(self._packet.ethernet_type, EthernetType.ARP)

    def test__arp_ps__getter__hrtype(self) -> None:
        """
        Validate that the '_hrtype' attribute getter provides correct value.
        """

        self.assertIs(self._packet.hrtype, self._arp__hrtype)

    def test__arp_ps__getter__prtype(self) -> None:
        """
        Validate that the '_prtype' attribute getter provides correct value.
        """

        self.assertIs(self._packet.prtype, self._arp__prtype)

    def test__arp_ps__getter__hrlen(self) -> None:
        """
        Validate that the '_hrlen' attribute getter provides correct value.
        """

        self.assertIs(self._packet.hrlen, self._arp__hrlen)

    def test__arp_ps__getter__prlen(self) -> None:
        """
        Validate that the '_prlen' attribute getter provides correct value.
        """

        self.assertIs(self._packet.prlen, self._arp__prlen)

    def test__arp_ps__getter__oper(self) -> None:
        """
        Validate that the '_oper' attribute getter provides correct value.
        """

        self.assertIs(self._packet.oper, self._arp__oper)

    def test__arp_ps__getter__sha(self) -> None:
        """
        Validate that the '_sha' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.sha, self._arp__sha)

    def test__arp_ps__getter__spa(self) -> None:
        """
        Validate that the '_spa' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.spa, self._arp__spa)

    def test__arp_ps__getter__tha(self) -> None:
        """
        Validate that the '_tha' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.tha, self._arp__tha)

    def test__arp_ps__getter__tpa(self) -> None:
        """
        Validate that the '_tpa' attribute getter provides correct value.
        """

        self.assertEqual(self._packet.tpa, self._arp__tpa)
