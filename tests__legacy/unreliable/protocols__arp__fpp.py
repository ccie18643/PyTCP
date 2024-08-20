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
# tests/unit/arp_fpp.py -  Tests specific for ARP FPP module.
#
# ver 3.0.0
#

import struct

from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.arp.fpp import ArpIntegrityError, ArpParser, ArpSanityError
from protocols.arp.base import (
    ARP_HEADER_LEN,
    ArpHardwareLength,
    ArpHardwareType,
    ArpProtocolLength,
    ArpProtocolType,
)
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


class TestArpParser(TestCase):
    """
    ARP Parser unit test class.
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
        self._arp__test_frame = bytearray(ARP__TEST_FRAME)

    def test__arp_fpp____init____success(self) -> None:
        """
        Validate that the class constructor creates packet
        correctly reflecting the provided frame.
        """

        packet_rx = PacketRx(self._arp__test_frame)
        self.assertEqual(packet_rx.frame, memoryview(self._arp__test_frame))

        packet = ArpParser(packet_rx)
        self.assertEqual(packet.frame, memoryview(self._arp__test_frame))

        self.assertIs(packet.hrtype, self._arp__hrtype)
        self.assertIs(packet.prtype, self._arp__prtype)
        self.assertIs(packet.hrlen, self._arp__hrlen)
        self.assertIs(packet.prlen, self._arp__prlen)
        self.assertIs(packet.oper, self._arp__oper)
        self.assertEqual(packet.sha, self._arp__sha)
        self.assertEqual(packet.spa, self._arp__spa)
        self.assertEqual(packet.tha, self._arp__tha)
        self.assertEqual(packet.tpa, self._arp__tpa)

    def test__arp_fpp____init____failure_integrity__frame_too_short(
        self,
    ) -> None:
        """
        Validate that the integrity check fails when the provided
        frame is too short.
        """

        self._arp__test_frame = self._arp__test_frame[: ARP_HEADER_LEN - 1]

        packet_rx = PacketRx(self._arp__test_frame)

        with self.assertRaises(ArpIntegrityError) as error:
            ArpParser(PacketRx(self._arp__test_frame))

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ARP] The minimum packet length must be "
            f"{ARP_HEADER_LEN} bytes, got {len(packet_rx.frame)} bytes.",
        )

    def test__arp_fpp____init____failure_sanity__incorrect_hrtype(
        self,
    ) -> None:
        """
        Validate that the sanity check fails when the value of the
        'hrtype' field is not correct.
        """

        struct.pack_into("! H", self._arp__test_frame, 0, bad_hrtype := 0x1234)

        packet_rx = PacketRx(self._arp__test_frame)

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][ARP] The 'hrtype' field value must be one of "
            f"{ArpHardwareType.get_core_values()}, got '{bad_hrtype}'.",
        )

    def test__arp_fpp____init____failure_sanity__incorrect_prtype(
        self,
    ) -> None:
        """
        Validate that the sanity check fails when the value of the
        'prtype' field is not correct.
        """

        struct.pack_into("! H", self._arp__test_frame, 2, bad_prtype := 0x1234)

        packet_rx = PacketRx(self._arp__test_frame)

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][ARP] The 'prtype' field value must be one of "
            f"{ArpProtocolType.get_core_values()}, got '{bad_prtype}'.",
        )

    def test__arp_fpp____init____failure_sanity__incorrect_hrlen(
        self,
    ) -> None:
        """
        Validate that the sanity check fails when the value of the
        'hrlen' field is not correct.
        """

        struct.pack_into("! B", self._arp__test_frame, 4, bad_hrlen := 0xFF)

        packet_rx = PacketRx(self._arp__test_frame)

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][ARP] The 'hrlen' field value must be one of "
            f"{ArpHardwareLength.get_core_values()}, got '{bad_hrlen}'.",
        )

    def test__arp_fpp____init____failure_sanity__incorrect_prlen(
        self,
    ) -> None:
        """
        Validate that the sanity check fails when the value of the
        'prlen' field is not correct.
        """

        struct.pack_into("! B", self._arp__test_frame, 5, bad_prlen := 0xFF)

        packet_rx = PacketRx(self._arp__test_frame)

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][ARP] The 'prlen' field value must be one of "
            f"{ArpProtocolLength.get_core_values()}, got '{bad_prlen}'.",
        )

    def test__arp_fpp____len__(self) -> None:
        """
        Verify that the '__len__()' dunder provides valid packet length.
        """

        packet_rx = PacketRx(self._arp__test_frame)
        packet = ArpParser(packet_rx)

        self.assertEqual(len(packet), len(self._arp__test_frame))
