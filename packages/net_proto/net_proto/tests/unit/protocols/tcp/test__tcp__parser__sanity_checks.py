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
Module contains tests for the TCP packet sanity checks.

net_proto/tests/unit/protocols/tcp/test__tcp__parser__sanity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import PacketRx, TcpParser, TcpSanityError


@parameterized_class(
    [
        {
            "_description": "The 'sport' field equals 0.",
            # TCP wire frame (20 bytes, header-only):
            #   Bytes 0-1   : 0x0000     -> sport=0 (sanity violation)
            #   Bytes 2-3   : 0xd431     -> dport=54321
            #   Bytes 4-7   : 0x0012d687 -> seq=1234567
            #   Bytes 8-11  : 0x0074cbb1 -> ack=7654321
            #   Bytes 12-13 : 0x5010     -> hlen=20, flags=ACK
            #   Bytes 14-15 : 0x2b67     -> win=11111
            #   Bytes 16-17 : 0x0d97     -> cksum (valid for init=0)
            #   Bytes 18-19 : 0x0000     -> urg=0
            "_frame_rx": (b"\x00\x00\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x10\x2b\x67" b"\x0d\x97\x00\x00"),
            "_error_message": "The 'sport' field must be greater than 0. Got: 0",
        },
        {
            "_description": "The 'dport' field equals 0.",
            # Bytes 2-3 : 0x0000 -> dport=0 (sanity violation); sport=12345.
            "_frame_rx": (b"\x30\x39\x00\x00\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x10\x2b\x67" b"\xb1\x8f\x00\x00"),
            "_error_message": "The 'dport' field must be greater than 0. Got: 0",
        },
        {
            "_description": "The SYN and FIN flags are set simultaneously.",
            # Bytes 12-13 : 0x5013 -> hlen=20, flags=A,S,F (ACK|SYN|FIN).
            "_frame_rx": (b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x13\x2b\x67" b"\xdd\x5a\x00\x00"),
            "_error_message": "The 'flag_syn' and 'flag_fin' must not be set simultaneously.",
        },
        {
            "_description": "The SYN and RST flags are set simultaneously.",
            # Bytes 12-13 : 0x5016 -> hlen=20, flags=A,R,S (ACK|RST|SYN).
            "_frame_rx": (b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x16\x2b\x67" b"\xdd\x57\x00\x00"),
            "_error_message": "The 'flag_syn' and 'flag_rst' must not be set simultaneously.",
        },
        {
            "_description": "The FIN and RST flags are set simultaneously.",
            # Bytes 12-13 : 0x5015 -> hlen=20, flags=A,R,F (ACK|RST|FIN).
            "_frame_rx": (b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x15\x2b\x67" b"\xdd\x58\x00\x00"),
            "_error_message": "The 'flag_fin' and 'flag_rst' must not be set simultaneously.",
        },
        {
            "_description": "The ACK flag is not set when FIN flag is set.",
            # Bytes 12-13 : 0x5001 -> hlen=20, flags=F only (no ACK).
            "_frame_rx": (b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x01\x2b\x67" b"\xdd\x6c\x00\x00"),
            "_error_message": "The 'flag_ack' must be set when 'flag_fin' is set.",
        },
    ]
)
class TestTcpParserSanityChecks(TestCase):
    """
    The TCP packet parser sanity checks tests.

    The TCP parser reads only 'ip.payload_len' and 'ip.pshdr_sum' from
    the containing IP layer, so a SimpleNamespace stub is sufficient and
    the tests are agnostic to whether the carrier is IPv4 or IPv6.
    """

    _description: str
    _frame_rx: bytes
    _error_message: str

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IP layer
        attributes the TCP parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(self._frame_rx),
            pshdr_sum=0,
        )

    def test__tcp__parser__sanity_error(self) -> None:
        """
        Ensure the TCP packet parser raises TcpSanityError with the
        expected message for each frame that is structurally well-formed
        but logically inconsistent.

        Reference: RFC 9293 §3.1 (TCP header sanity).
        """

        with self.assertRaises(TcpSanityError) as error:
            TcpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][TCP] {self._error_message}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )
