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
Module contains tests for the ICMPv6 MLDv2 Report message parser
integrity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__parser__integrity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address
from net_proto import (
    ICMP6__MLD2__REPORT__LEN,
    Icmp6IntegrityError,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)


def _packet_rx_with_ip6(frame: bytes, *, ip6__dlen: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6' (dlen, pshdr_sum, src, dst, hop).
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame) if ip6__dlen is None else ip6__dlen,
            payload_len=len(frame) if ip6__dlen is None else ip6__dlen,
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
            "_description": (
                "ICMPv6 MLDv2 Report, the 'ICMP6__HEADER__LEN <= self._ip6__dlen' "
                "condition not met (frame shorter than ICMPv6 base header)."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report (truncated, < 4 bytes)
                #   Type     : 143 (MLDv2 Report)
                #   Code     : 0
                #   Checksum : 0x70-- (missing low byte)
                #   Frame len: 3 bytes
                b"\x8f\x00\x70"
            ),
            "_ip6__dlen": 3,
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=3, len(self._frame)=3"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Report, the 'self._ip6__dlen <= len(self._frame)' "
                "condition not met (declared IPv6 payload exceeds frame length)."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report (frame shorter than declared ip6__dlen)
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x70ff
                #   Reserved     : 0x0000
                #   Record count : 0x00-- (missing last byte)
                #   Frame len    : 7 bytes
                b"\x8f\x00\x70\xff\x00\x00\x00"
            ),
            "_ip6__dlen": 8,
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=8, len(self._frame)=7"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Report, the 'ICMP6__MLD2__REPORT__LEN <= ip6__dlen' "
                "condition not met (ip6__dlen below the fixed report header size)."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report (minimum 8-byte header, but ip6__dlen=7)
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x70ff
                #   Reserved     : 0x0000
                #   Record count : 0x0000
                b"\x8f\x00\x70\xff\x00\x00\x00\x00"
            ),
            "_ip6__dlen": 7,
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__MLD2__REPORT__LEN <= ip6__dlen <= len(frame)' "
                    "is not met. Got: ICMP6__MLD2__REPORT__LEN=8, ip6__dlen=7, len(frame)=8"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Report, the "
                "'record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN <= ip6__dlen' "
                "condition not met (record count claims more than the payload holds)."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x1582
                #   Reserved     : 0x0000
                #   Record count : 0x0002 (two records claimed — only one fits)
                #   Record [0]   : Type 0x01, Aux 0, Src 2, mcast ff02::1,
                #                  sources 2001:db8::1, 2001:db8::2 (total 52 bytes)
                #   Frame len    : 60 bytes
                b"\x8f\x00\x15\x82\x00\x00\x00\x02\x01\x00\x00\x02\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_ip6__dlen": None,
            "_results": {
                "error_message": (
                    "The condition 'record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN "
                    "<= ip6__dlen' is not met. Got: record_offset=60, "
                    "ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN=20, ip6__dlen=60"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Report, the 'record_offset == ip6__dlen' condition "
                "not met (declared payload length shorter than the parsed records)."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x1583
                #   Reserved     : 0x0000
                #   Record count : 0x0001
                #   Record [0]   : Type 0x01, Aux 0, Src 2, mcast ff02::1,
                #                  sources 2001:db8::1, 2001:db8::2 (total 52 bytes)
                #   Frame len    : 60 bytes, ip6__dlen=59 (one byte short)
                b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_ip6__dlen": 59,
            "_results": {
                "error_message": (
                    "The condition 'record_offset == ip6__dlen' is not met. " "Got: record_offset=60, ip6__dlen=59"
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report with invalid checksum (all zeros).",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type         : 143
                #   Code         : 0
                #   Checksum     : 0x0000 (invalid; valid value with pshdr_sum=0 is 0x70ff)
                #   Reserved     : 0x0000
                #   Record count : 0x0000
                b"\x8f\x00\x00\x00\x00\x00\x00\x00"
            ),
            "_ip6__dlen": None,
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp6Mld2MessageReportParserIntegrityChecks(TestCase):
    """
    The ICMPv6 MLDv2 Report message parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _ip6__dlen: int | None
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build a PacketRx with the parametrized frame and IPv6 payload length.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx, ip6__dlen=self._ip6__dlen)

    def test__icmp6__mld2__message__report__parser__integrity_error(self) -> None:
        """
        Ensure the ICMPv6 parser raises Icmp6IntegrityError on malformed
        MLDv2 Report frames with the expected message.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv6] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp6Mld2MessageReportParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv6 MLDv2 Report integrity validator.
    """

    def test__icmp6__mld2__message__report__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame whose IPv6 payload length equals
        ICMP6__MLD2__REPORT__LEN (8) — a bare, record-less MLDv2 Report —
        passes integrity checks and parses successfully.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        # ICMPv6 MLDv2 Report at minimum length (8 bytes), no records
        #   Type         : 143 (MLDv2 Report)
        #   Code         : 0
        #   Checksum     : 0x70ff (valid with pshdr_sum=0)
        #   Reserved     : 0x0000
        #   Record count : 0x0000
        frame = b"\x8f\x00\x70\xff\x00\x00\x00\x00"

        self.assertEqual(
            len(frame),
            ICMP6__MLD2__REPORT__LEN,
            msg="Fixture must match ICMP6__MLD2__REPORT__LEN.",
        )

        Icmp6Parser(_packet_rx_with_ip6(frame))

    def test__icmp6__mld2__message__report__parser__integrity__single_record_accepted(self) -> None:
        """
        Ensure a valid MLDv2 Report carrying a single record passes
        integrity checks and walks the record-offset loop cleanly.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        # ICMPv6 MLDv2 Report, one record
        #   Type         : 143
        #   Code         : 0
        #   Checksum     : 0x70fa (valid with pshdr_sum=0)
        #   Reserved     : 0x0000
        #   Record count : 0x0001
        #   Record [0]   : Type 0x01 (MODE_IS_INCLUDE), Aux 0, Src 0,
        #                  mcast ff02::1 (20 bytes)
        frame = (
            b"\x8f\x00\x70\xfa\x00\x00\x00\x01\x01\x00\x00\x00\xff\x02\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        )

        Icmp6Parser(_packet_rx_with_ip6(frame))
