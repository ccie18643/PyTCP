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
Module contains tests for the TCP packet integrity checks.

net_proto/tests/unit/protocols/tcp/test__tcp__parser__integrity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import override
from unittest import TestCase

from net_proto import PacketRx, TcpIntegrityError, TcpParser
from net_proto.tests.lib.parameterized import parameterized_class

# A valid 24-byte TCP frame used as the baseline for parser-integrity
# fixtures. Callers perturb exactly one aspect (payload_len, hlen byte,
# checksum, or option length) to exercise individual integrity branches.
#
# TCP wire frame (24 bytes = 20-byte header + 4-byte Nop-padded options):
#   Bytes 0-1   : 0x3039     -> sport=12345
#   Bytes 2-3   : 0xd431     -> dport=54321
#   Bytes 4-7   : 0x0012d687 -> seq=1234567
#   Bytes 8-11  : 0x0074cbb1 -> ack=7654321
#   Bytes 12-13 : 0x6010     -> hlen=24, flags=ACK
#   Bytes 14-15 : 0x2b67     -> win=11111
#   Bytes 16-17 : 0xcb5b     -> cksum (valid for init=0)
#   Bytes 18-19 : 0x0000     -> urg=0
#   Bytes 20-23 : 0x01010101 -> 4 Nop padding options
_BASELINE_FRAME = (
    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67" b"\xcb\x5b\x00\x00\x01\x01\x01\x01"
)


@parameterized_class(
    [
        {
            "_description": "The 'ip__payload_len' is lower than TCP__HEADER__LEN.",
            "_frame_rx": _BASELINE_FRAME,
            "_ip__payload_len": 19,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'TCP__HEADER__LEN <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, "
                "self._ip__payload_len=19, len(self._frame)=24"
            ),
        },
        {
            "_description": "The 'ip__payload_len' is higher than the frame length.",
            "_frame_rx": _BASELINE_FRAME,
            "_ip__payload_len": 25,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'TCP__HEADER__LEN <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, "
                "self._ip__payload_len=25, len(self._frame)=24"
            ),
        },
        {
            "_description": "The header 'hlen' field (16) is lower than TCP__HEADER__LEN.",
            # Byte 12 = 0x4c encodes hlen=16 (0x4 << 2 bits = 16) in the hlen nibble.
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x4c\x10\x2b\x67" b"\xdf\x5b\x00\x00\x01\x01\x01\x01"
            ),
            "_ip__payload_len": 24,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, hlen=16, "
                "self._ip__payload_len=24, len(self._frame)=24"
            ),
        },
        {
            "_description": "The header 'hlen' field (28) exceeds 'ip__payload_len'.",
            # Byte 12 = 0x70 encodes hlen=28 (0x7 << 2 = 28).
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x70\x10\x2b\x67" b"\xbb\x5b\x00\x00\x01\x01\x01\x01"
            ),
            "_ip__payload_len": 24,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The condition 'TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, hlen=28, "
                "self._ip__payload_len=24, len(self._frame)=24"
            ),
        },
        {
            "_description": "Packet has incorrect checksum.",
            # 41-byte frame with intentionally invalid cksum bytes 16-17 = 0xbe86.
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                b"\xbe\x86\x00\x00\x03\x03\x0a\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46"
            ),
            "_ip__payload_len": 41,
            "_ip__pshdr_sum": 0,
            "_error_message": "The packet checksum must be valid.",
        },
        {
            "_description": "TCP option 'len' field is 1 (below the minimum 2).",
            # Bytes 20-23 : 0xff 0x01 0x00 0x00 -> first option has type=0xff, len=1.
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67" b"\xce\x5b\x00\x00\xff\x01\x00\x00"
            ),
            "_ip__payload_len": 24,
            "_ip__pshdr_sum": 0,
            "_error_message": "The TCP option length must be greater than 1. Got: 1.",
        },
        {
            "_description": "TCP option 'len' field extends past 'hlen'.",
            # Bytes 20-23 : 0xff 0x05 0x00 0x00 -> first option has type=0xff, len=5,
            # which advances offset beyond the 4-byte options area (hlen=24).
            "_frame_rx": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67" b"\xce\x57\x00\x00\xff\x05\x00\x00"
            ),
            "_ip__payload_len": 24,
            "_ip__pshdr_sum": 0,
            "_error_message": (
                "The TCP option length must not extend past the header length. " "Got: offset=25, hlen=24"
            ),
        },
    ]
)
class TestTcpParserIntegrityChecks(TestCase):
    """
    The TCP packet parser integrity checks tests.

    The TCP parser reads only 'ip.payload_len' and 'ip.pshdr_sum' from
    the containing IP layer, so a SimpleNamespace stub is sufficient and
    the tests are agnostic to whether the carrier is IPv4 or IPv6.
    """

    _description: str
    _frame_rx: bytes
    _ip__payload_len: int
    _ip__pshdr_sum: int
    _error_message: str

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IP layer
        attributes the TCP parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=self._ip__payload_len,
            pshdr_sum=self._ip__pshdr_sum,
        )

    def test__tcp__parser__integrity_error(self) -> None:
        """
        Ensure the TCP packet parser raises TcpIntegrityError with the
        expected message for each malformed frame.

        Reference: RFC 9293 §3.1 (TCP header integrity).
        """

        with self.assertRaises(TcpIntegrityError) as error:
            TcpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][TCP] {self._error_message}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestTcpParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the TCP parser integrity validator. Exercises the
    positive path — the shortest frame that passes every integrity check
    — so a future regression that tightens the constraint is caught as a
    test failure rather than silently masked by the parametrized
    rejection fixtures.
    """

    def test__tcp__parser__integrity__baseline_accepted(self) -> None:
        """
        Ensure the baseline 24-byte frame (20-byte header + 4 Nop
        options, valid checksum) passes the integrity check and parses
        successfully.

        Reference: RFC 9293 §3.1 (TCP header integrity).
        """

        self.assertEqual(
            len(_BASELINE_FRAME),
            24,
            msg="Baseline fixture must be exactly 24 bytes (header + 4 Nop options).",
        )

        packet_rx = PacketRx(_BASELINE_FRAME)
        packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(_BASELINE_FRAME),
            pshdr_sum=0,
        )

        parser = TcpParser(packet_rx)

        self.assertEqual(
            parser.sport,
            12345,
            msg="Baseline-frame parser must report sport=12345.",
        )
        self.assertEqual(
            parser.dport,
            54321,
            msg="Baseline-frame parser must report dport=54321.",
        )
        self.assertEqual(
            parser.hlen,
            24,
            msg="Baseline-frame parser must report hlen=24.",
        )

    def test__tcp__parser__integrity__trailing_bytes_accepted(self) -> None:
        """
        Ensure a frame whose raw length exceeds 'ip__payload_len' (the TCP
        segment is followed by lower-layer padding) still parses: both
        integrity bounds end in 'ip__payload_len <= len(frame)', so
        trailing bytes beyond the IP-declared payload are tolerated, not
        rejected, and the payload is sliced at 'ip__payload_len'.

        Reference: RFC 9293 §3.1 (TCP header integrity).
        """

        # Baseline 24-byte segment (valid checksum) followed by 4 octets of
        # lower-layer padding. ip__payload_len=24 is strictly less than
        # len(frame)=28.
        frame = _BASELINE_FRAME + b"\x00\x00\x00\x00"

        packet_rx = PacketRx(frame)
        packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
            payload_len=len(_BASELINE_FRAME),
            pshdr_sum=0,
        )

        parser = TcpParser(packet_rx)

        self.assertEqual(
            parser.hlen,
            24,
            msg="Trailing-padding frame must parse with hlen=24.",
        )
        self.assertEqual(
            bytes(parser.payload),
            b"",
            msg="Payload must end at ip__payload_len, excluding the lower-layer padding.",
        )
