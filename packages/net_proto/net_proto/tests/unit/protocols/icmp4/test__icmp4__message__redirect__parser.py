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
Module contains tests for the ICMPv4 Redirect message parser operation
and sanity checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__redirect__parser.py

ver 3.0.10
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Icmp4MessageRedirect,
    Icmp4Parser,
    Icmp4RedirectCode,
    Icmp4SanityError,
    Ip4Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class

_EMBEDDED = (
    b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
    b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
    b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
)


def _packet_rx_with_ip4(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub whose 'payload_len' matches
    the full frame.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = cast(Ip4Parser, SimpleNamespace(payload_len=len(frame)))
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Redirect, code 1 (Host), gateway 10.0.1.1, no data.",
            "_frame_rx": b"\x05\x01\xef\xfd\x0a\x00\x01\x01",
            "_results": {
                "message": Icmp4MessageRedirect(
                    code=Icmp4RedirectCode.HOST,
                    cksum=0xEFFD,
                    gateway=Ip4Address("10.0.1.1"),
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Redirect, code 0 (Network), gateway 192.168.1.254, no data.",
            "_frame_rx": b"\x05\x00\x38\x59\xc0\xa8\x01\xfe",
            "_results": {
                "message": Icmp4MessageRedirect(
                    code=Icmp4RedirectCode.NETWORK,
                    cksum=0x3859,
                    gateway=Ip4Address("192.168.1.254"),
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Redirect, code 1 (Host), gateway 10.0.1.1, embedded IP+8 UDP.",
            "_frame_rx": b"\x05\x01\x8e\x02\x0a\x00\x01\x01" + _EMBEDDED,
            "_results": {
                "message": Icmp4MessageRedirect(
                    code=Icmp4RedirectCode.HOST,
                    cksum=0x8E02,
                    gateway=Ip4Address("10.0.1.1"),
                    data=_EMBEDDED,
                ),
            },
        },
    ]
)
class TestIcmp4MessageRedirectParser(TestCase):
    """
    The ICMPv4 Redirect message parser-operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__icmp4__message__redirect__parser__dispatches_to_redirect(self) -> None:
        """
        Ensure that an inbound frame whose ICMPv4 type byte is 5 routes
        through Icmp4Parser to an Icmp4MessageRedirect instance — not to
        Icmp4MessageUnknown.

        Reference: RFC 792 (Redirect type 5).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx)

        Icmp4Parser(packet_rx)

        self.assertIsInstance(
            packet_rx.icmp4.message,
            Icmp4MessageRedirect,
            msg=f"Type-5 frame must route to Icmp4MessageRedirect for case: {self._description}",
        )

    def test__icmp4__message__redirect__parser__decoded_message_matches(self) -> None:
        """
        Ensure the decoded Redirect message equals the expected dataclass
        (code, cksum, gateway, data round-trip cleanly).

        Reference: RFC 792 (Redirect wire format).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx)

        Icmp4Parser(packet_rx)

        self.assertEqual(
            packet_rx.icmp4.message,
            self._results["message"],
            msg=f"Unexpected decoded Redirect message for case: {self._description}",
        )


class TestIcmp4MessageRedirectParserSanity(TestCase):
    """
    The ICMPv4 Redirect message parser sanity-check tests.
    """

    def test__icmp4__message__redirect__parser__unknown_code_rejected(self) -> None:
        """
        Ensure the parser raises Icmp4SanityError when the Redirect
        'code' field is outside the RFC 792 assigned range (0..3).

        Reference: RFC 792 (Redirect codes 0..3 only).
        """

        # ICMPv4 Redirect with code 4 (unassigned) and a VALID checksum
        # (so the parser reaches the sanity check rather than tripping
        # the integrity checksum guard first).
        #   Type     : 5 (Redirect)
        #   Code     : 4 (unassigned — sanity violation)
        #   Checksum : 0xeffa (valid over the 8-byte message)
        #   Gateway  : 10.0.1.1
        packet_rx = _packet_rx_with_ip4(b"\x05\x04\xef\xfa\x0a\x00\x01\x01")

        with self.assertRaises(Icmp4SanityError) as error:
            Icmp4Parser(packet_rx)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][ICMPv4] The 'code' field of the ICMPv4 Redirect "
            "message must be one of [0, 1, 2, 3]. Got: 4.",
            msg="Unexpected sanity-error message for unknown Redirect code.",
        )
