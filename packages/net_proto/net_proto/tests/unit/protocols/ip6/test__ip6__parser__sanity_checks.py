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
This module contains tests for the IPv6 packet sanity checks.

net_proto/tests/unit/protocols/ip6/test__ip6__parser__sanity_checks.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Ip6Parser, Ip6SanityError, PacketRx


@parameterized_class(
    [
        {
            "_description": "Hop limit is zero.",
            # 40-byte IPv6 frame with hop=0 (byte 7). Remaining fields
            # match the baseline from the integrity tests so the
            # integrity stage passes and the sanity validator raises on
            # 'hop == 0'.
            #
            # IPv6 wire frame (40 bytes, header only):
            #   Byte  0     : 0x60   -> ver=6
            #   Bytes 1-3   : 0x000000 -> dscp=0, ecn=0, flow=0
            #   Bytes 4-5   : 0x0000 -> dlen=0
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0x00   -> hop=0 (triggers sanity check)
            #   Bytes 8-23  : src=1001:2002:3003:4004:5005:6006:7007:8008
            #   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x00\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "error_message": "The 'hop' field must not be 0. Got: 0",
                "pointer": 7,
            },
        },
        {
            "_description": "Source address is a multicast address.",
            # Bytes 8-23 set to ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
            # (inside ff00::/8). hop is restored to 1 so the hop check
            # does not preempt the multicast-src check.
            #
            # IPv6 wire frame (40 bytes, header only):
            #   Byte  0     : 0x60   -> ver=6
            #   Bytes 1-3   : 0x000000 -> dscp=0, ecn=0, flow=0
            #   Bytes 4-5   : 0x0000 -> dlen=0
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0x01   -> hop=1
            #   Bytes 8-23  : src=ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
            #                (multicast — triggers sanity check)
            #   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x01\xff\xff\xff\xff\xff\xff\xff\xff"
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "error_message": (
                    "The 'src' field must not be a multicast address. "
                    "Got: Ip6Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')"
                ),
                "pointer": 8,
            },
        },
        {
            "_description": "Source address is a link-local multicast address (ff02::1).",
            # Bytes 8-23 encode ff02::1 (all-nodes multicast). This
            # exercises the low-end of the ff00::/8 multicast range, not
            # just the all-ones corner case.
            #
            # IPv6 wire frame (40 bytes, header only):
            #   Byte  0     : 0x60   -> ver=6
            #   Bytes 1-3   : 0x000000 -> dscp=0, ecn=0, flow=0
            #   Bytes 4-5   : 0x0000 -> dlen=0
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0x40   -> hop=64
            #   Bytes 8-23  : src=ff02::1 (all-nodes multicast)
            #   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x40\xff\x02\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "error_message": ("The 'src' field must not be a multicast address. Got: Ip6Address('ff02::1')"),
                "pointer": 8,
            },
        },
        {
            "_description": "Source address is the IPv6 loopback (::1).",
            # Bytes 8-23 encode ::1 (the IPv6 loopback address).
            # RFC 4291 §2.5.3 — "The loopback address must not be
            # used as the source address in IPv6 packets sent outside
            # of a single node." Direct analog of the IPv4 §3.2.1.3(g)
            # loopback ban.
            #
            # IPv6 wire frame (40 bytes, header only):
            #   Byte  0     : 0x60   -> ver=6
            #   Bytes 1-3   : 0x000000 -> dscp=0, ecn=0, flow=0
            #   Bytes 4-5   : 0x0000 -> dlen=0
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0x40   -> hop=64
            #   Bytes 8-23  : src=::1 (loopback)
            #   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x40\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "error_message": ("The 'src' field must not be a loopback address. Got: Ip6Address('::1')"),
                "pointer": 8,
            },
        },
    ],
)
class TestIp6ParserSanityChecks(TestCase):
    """
    The IPv6 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx so it can be fed to
        Ip6Parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__ip6__parser__sanity_error(self) -> None:
        """
        Ensure the IPv6 packet parser raises Ip6SanityError with the
        expected message for each semantically invalid frame.

        Reference: RFC 8200 §3 (IPv6 header layout).
        """

        with self.assertRaises(Ip6SanityError) as error:
            Ip6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv6] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )

    def test__ip6__parser__sanity_error_pointer(self) -> None:
        """
        Ensure the IPv6 packet parser sets the canonical RFC 4443
        Parameter Problem 'pointer' on the raised Ip6SanityError so
        the packet handler can emit Code 0 (erroneous header field
        encountered) with the correct byte offset of the offending
        field.

        Reference: RFC 4443 §3.4 (Parameter Problem pointer).
        Reference: RFC 1122 §3.2.2.5 (host SHOULD generate Param Problem
        on inbound IP-header errors).
        """

        with self.assertRaises(Ip6SanityError) as error:
            Ip6Parser(self._packet_rx)

        self.assertEqual(
            error.exception.pointer,
            self._results["pointer"],
            msg=f"Unexpected sanity-error pointer for case: {self._description}",
        )
