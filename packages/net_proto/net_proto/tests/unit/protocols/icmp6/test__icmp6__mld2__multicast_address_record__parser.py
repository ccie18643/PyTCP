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
Module contains tests for the ICMPv6 MLDv2 Multicast Address Record parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__multicast_address_record__parser.py

ver 3.0.10
"""

from typing import Any
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "MLDv2 Multicast Address Record (MODE_IS_INCLUDE, no sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen  : 0
                #   Src count : 0
                #   Multicast : ff02::1
                b"\x01\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (MODE_IS_EXCLUDE, no sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x02 (MODE_IS_EXCLUDE)
                #   Aux dlen  : 0
                #   Src count : 0
                #   Multicast : ff02::1
                b"\x02\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (CHANGE_TO_INCLUDE, no sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x03 (CHANGE_TO_INCLUDE)
                #   Aux dlen  : 0
                #   Src count : 0
                #   Multicast : ff02::1
                b"\x03\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (CHANGE_TO_EXCLUDE, no sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x04 (CHANGE_TO_EXCLUDE)
                #   Aux dlen  : 0
                #   Src count : 0
                #   Multicast : ff02::1
                b"\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (ALLOW_NEW_SOURCES, no sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x05 (ALLOW_NEW_SOURCES)
                #   Aux dlen  : 0
                #   Src count : 0
                #   Multicast : ff02::1
                b"\x05\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (BLOCK_OLD_SOURCES, no sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x06 (BLOCK_OLD_SOURCES)
                #   Aux dlen  : 0
                #   Src count : 0
                #   Multicast : ff02::1
                b"\x06\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (3 sources, no aux data).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen  : 0
                #   Src count : 3
                #   Multicast : ff02::1
                #   Sources   : 2001:db8::1, 2001:db8::2, 2001:db8::3
                b"\x01\x00\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x03"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
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
            "_description": "MLDv2 Multicast Address Record (no sources, 16-byte aux data).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen  : 4 (32-bit words → 16 bytes)
                #   Src count : 0
                #   Multicast : ff02::1
                #   Aux data  : "0123456789ABCDEF"
                b"\x01\x04\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    aux_data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "MLDv2 Multicast Address Record (3 sources, 16-byte aux data).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Type      : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen  : 4 (32-bit words → 16 bytes)
                #   Src count : 3
                #   Multicast : ff02::1
                #   Sources   : 2001:db8::1, 2001:db8::2, 2001:db8::3
                #   Aux data  : "0123456789ABCDEF"
                b"\x01\x04\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x03\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "record": Icmp6Mld2MulticastAddressRecord(
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
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__icmp6__mld2__multicast_address_record__parser__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' reconstructs the reference record from the
        fixture bytes, ignoring any trailing payload supplied after the
        declared source/aux-data extent.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        trailing_garbage = b"ZH0PA"
        record = Icmp6Mld2MulticastAddressRecord.from_buffer(self._frame_rx + trailing_garbage)

        self.assertEqual(
            record,
            self._results["record"],
            msg=f"Parsed record mismatch for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__parser__consumes_declared_length(self) -> None:
        """
        Ensure 'from_buffer()' treats the declared header extents
        (number_of_sources × IP6_ADDRESS_LEN + aux_data_len × 4) as the
        authoritative boundary — anything past that offset must not be
        absorbed into the record even when the buffer continues.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        record = Icmp6Mld2MulticastAddressRecord.from_buffer(self._frame_rx + b"extraneous trailing bytes")

        self.assertEqual(
            len(record),
            len(self._frame_rx),
            msg=("Parsed record length must match the declared fixture length " f"for case: {self._description}"),
        )
