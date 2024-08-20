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


"""
This module contains tests for the ICMPv6 MLDv2 Multicast Address Record
assembler & parser argument asserts.

tests/unit/protocols/icmp6/test__icmp6__mld2__multicast_address_record__asserts.py

ver 3.0.0
"""

from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)


class TestIcmp6Mld2MulticastAddressRecordAsserts(TestCase):
    """
    The ICMPv6 'MLDv2 Multicast Address Record' assembler & parser
    constructor argument assert tests.
    """

    def test__icmp6__mld2__multicast_address_record__aux_data_len__not_4_bytes_alligned(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 'MLDv2 Multicast Address Record' assembler constructor
        raises an exception when the length of the provided 'aux_data' argument
        is not 4 bytes aligned.
        """

        with self.assertRaises(AssertionError):
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                multicast_address=Ip6Address("ff02::1"),
                aux_data=b"X" * (16 + 1),
            )

    def test__icmp6__mld2__multicast_address_record__multicast_address__not_multicast(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 'MLDv2 Multicast Address Record' assembler constructor
        raises an exception when the provided 'multicast_address' argument is not
        a valid multicast address.
        """

        with self.assertRaises(AssertionError):
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                multicast_address=Ip6Address("2001::1"),
            )

    def test__icmp6__mld2__multicast_address_record__source_addresses__not_unicast(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 'MLDv2 Multicast Address Record' assembler raises
        an exception when any element of the provided 'source_addresses'
        argument is not a valid unicast address.
        """

        with self.assertRaises(AssertionError):
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                multicast_address=Ip6Address("ff02::1"),
                source_addresses=[
                    Ip6Address("2001::1"),
                    Ip6Address("ff02::1"),
                    Ip6Address("2001::2"),
                ],
            )
