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

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__parser.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub. 'hop' is set to 1 so the
    MLDv2 Report sanity check (RFC 3810 — hop must be 1) passes.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
            pshdr_sum=0,
            src=Ip6Address(),
            dst=Ip6Address(),
            hop=1,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Report message, no records.",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type         : 143 (MLDv2 Report)
                #   Code         : 0
                #   Checksum     : 0x70ff
                #   Reserved     : 0x0000
                #   Record count : 0x0000
                b"\x8f\x00\x70\xff\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6Mld2MessageReport(
                    cksum=0x70FF,
                    records=[],
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, single record (MODE_IS_INCLUDE, two sources).",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x1583
                #   Reserved     : 0x0000
                #   Record count : 0x0001
                #   Record [0]   : Type 0x01 (MODE_IS_INCLUDE), Aux 0, Src 2
                #                  Multicast ff02::1, Sources 2001:db8::1, 2001:db8::2
                b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_results": {
                "message": Icmp6Mld2MessageReport(
                    cksum=0x1583,
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
            "_description": "ICMPv6 MLDv2 Report message, four records (all record types exercised).",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x52f0
                #   Reserved     : 0x0000
                #   Record count : 0x0004
                #   Record [0]   : MODE_IS_INCLUDE, ff02::1, src 2001:db8::1,
                #                  aux "0123456789ABCDEF"
                #   Record [1]   : MODE_IS_EXCLUDE, ff02::2, srcs 2001:db8::2/3/4,
                #                  aux "0123456789ABCDEF" * 2
                #   Record [2]   : CHANGE_TO_INCLUDE, ff02::3, srcs 2001:db8::6/7/8/9
                #   Record [3]   : BLOCK_OLD_SOURCES, ff02::4,
                #                  aux "0123456789ABCDEF" * 4
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
            "_results": {
                "message": Icmp6Mld2MessageReport(
                    cksum=0x52F0,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[Ip6Address("2001:db8::1")],
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
                            aux_data=b"0123456789ABCDEF" * 4,
                        ),
                    ],
                ),
            },
        },
    ]
)
class TestIcmp6Mld2MessageReportParser(TestCase):
    """
    The ICMPv6 MLDv2 Report message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx)

    def test__icmp6__mld2__message__report__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6Mld2MessageReport whose
        fields match the expected reference message for each frame.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6Mld2MessageReport instance.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6Mld2MessageReport,
            msg=f"Parsed message must be Icmp6Mld2MessageReport for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the parsed
        MLDv2 Report message (the whole frame is consumed).

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__parser__number_of_records(self) -> None:
        """
        Ensure the parsed message's 'number_of_records' property matches
        the length of the reference record list.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)
        expected = cast(Icmp6Mld2MessageReport, self._results["message"]).number_of_records

        self.assertEqual(
            cast(Icmp6Mld2MessageReport, icmp6_parser.message).number_of_records,
            expected,
            msg=f"'number_of_records' must match the reference for case: {self._description}",
        )
