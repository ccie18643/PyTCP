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
Module contains tests for the ICMPv6 MLDv2 Report message parser.

tests/unit/protocols/icmp6/test__icmp6__mld2__report__parser.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.net_addr import Ip6Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    Icmp6Mld2ReportMessage,
)
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Report message, no records.",
            "_args": {
                "bytes": b"\x8f\x00\x70\xff\x00\x00\x00\x00",
            },
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    cksum=28927,
                    records=[],
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, single record.",
            "_args": {
                "bytes": (
                    b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    cksum=5507,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                                Ip6Address("2001:db8::2"),
                            ],
                        ),
                    ],
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, multiple records.",
            "_args": {
                "bytes": (
                    b"\x8f\x00\x52\xf0\x00\x00\x00\x04\x01\x04\x00\x01\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x31\x32\x33"
                    b"\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x02\x08\x00\x03"
                    b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                    b"\x03\x00\x00\x04\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x03\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x06\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x08\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x09\x06\x10\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x04\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    cksum=21232,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                            ],
                            aux_data=b"0123456789ABCDEF",
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                            multicast_address=Ip6Address("ff02::2"),
                            source_addresses=[
                                Ip6Address("2001:db8::2"),
                                Ip6Address("2001:db8::3"),
                                Ip6Address("2001:db8::4"),
                            ],
                            aux_data=b"0123456789ABCDEF0123456789ABCDEF",
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                            multicast_address=Ip6Address("ff02::3"),
                            source_addresses=[
                                Ip6Address("2001:db8::6"),
                                Ip6Address("2001:db8::7"),
                                Ip6Address("2001:db8::8"),
                                Ip6Address("2001:db8::9"),
                            ],
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                            multicast_address=Ip6Address("ff02::4"),
                            aux_data=(
                                b"0123456789ABCDEF0123456789ABCDEF"
                                b"0123456789ABCDEF0123456789ABCDEF"
                            ),
                        ),
                    ],
                ),
            },
        },
    ]
)
class TestIcmp6Mld2ReportParser(TestCasePacketRxIp6):
    """
    The ICMPv6 MLDv2 Report message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__message__mld2__report__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'from_bytes()' method
        creates a proper message object.
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
