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
This module contains tests for the ICMPv6 MLDv2 Multicast Address Record parser.

tests/unit/protocols/icmp6/test__icmp6__mld2__multicast_address_record__parser.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Mode Is Include).",
            "_args": {
                "bytes": (
                    b"\x01\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Mode Is Exclude).",
            "_args": {
                "bytes": (
                    b"\x02\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Change To Include).",
            "_args": {
                "bytes": (
                    b"\x03\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Change To Exclude).",
            "_args": {
                "bytes": (
                    b"\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Allow New Sources).",
            "_args": {
                "bytes": (
                    b"\x05\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Block Old Sources).",
            "_args": {
                "bytes": (
                    b"\x06\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record', multiple sources, no aux data."
            ),
            "_args": {
                "bytes": (
                    b"\x01\x00\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x03"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    source_addresses=[
                        Ip6Address("2001:db8::1"),
                        Ip6Address("2001:db8::2"),
                        Ip6Address("2001:db8::3"),
                    ],
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 'MLDv2 Multicast Address Record', no sources, aux data."
            ),
            "_args": {
                "bytes": (
                    b"\x01\x04\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    aux_data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 'MLDv2 Multicast Address Record', multiple sources, aux data."
            ),
            "_args": {
                "bytes": (
                    b"\x01\x04\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x03\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    source_addresses=[
                        Ip6Address("2001:db8::1"),
                        Ip6Address("2001:db8::2"),
                        Ip6Address("2001:db8::3"),
                    ],
                    aux_data=b"0123456789ABCDEF",
                ),
            },
        },
    ]
)
class TestIcmp6Mld2MulticastAddressRecordParser(TestCase):
    """
    The ICMPv6 MLDv2 Multicast Address Record parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__mld2__multicast_address_record__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record method 'from_bytes()'
        creates a proper message object.
        """

        self.assertEqual(
            Icmp6Mld2MulticastAddressRecord.from_bytes(
                self._args["bytes"] + b"ZH0PA"
            ),
            self._results["from_bytes"],
        )
