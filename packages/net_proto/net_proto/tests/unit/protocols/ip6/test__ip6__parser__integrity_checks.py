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
This module contains tests for the IPv6 packet integrity checks.

net_proto/tests/unit/protocols/ip6/test__ip6__parser__integrity_checks.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import Ip6IntegrityError, Ip6Parser, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class

# Valid 40-byte IPv6 frame used by the positive boundary test. The
# parametrized negative fixtures are derived from it by perturbing
# exactly one byte range.
#
# IPv6 wire frame (40 bytes, header only, no payload):
#   Byte  0     : 0x60 -> ver=6, dscp/ecn high nibble=0
#   Byte  1     : 0x00 -> dscp/ecn low nibble=0, flow high nibble=0
#   Bytes 2-3   : 0x0000 -> flow low 16 bits = 0
#   Bytes 4-5   : 0x0000 -> dlen=0 (payload length)
#   Byte  6     : 0xff   -> next=IpProto.RAW (255)
#   Byte  7     : 0x01   -> hop=1
#   Bytes 8-23  : src=1001:2002:3003:4004:5005:6006:7007:8008
#   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
_BASELINE_FRAME = (
    b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
    b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
)


@parameterized_class(
    [
        {
            "_description": "Frame shorter than IP6__HEADER__LEN (39 bytes).",
            # Truncated to 39 bytes so the 'len(frame) < IP6__HEADER__LEN'
            # branch of _validate_integrity fires before any header field
            # is evaluated.
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b"
            ),
            "_results": {
                "error_message": (
                    "The condition 'IP6__HEADER__LEN <= len(self._frame)' must be met. "
                    "Got: IP6__HEADER__LEN=40, len(self._frame)=39"
                ),
            },
        },
        {
            "_description": "Version field is not 6.",
            # Byte 0 = 0x50 encodes ver=5. The parser rejects any ver != 6
            # regardless of the remaining fields. Length equals exactly
            # IP6__HEADER__LEN so the first length check cannot fire.
            "_frame_rx": (
                b"\x50\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "error_message": "The 'ver' field must be 6. Got: 5",
            },
        },
        {
            "_description": "Declared dlen disagrees with the frame length (extra payload byte).",
            # 41-byte frame: baseline 40-byte header + 1 trailing byte,
            # but bytes 4-5 (dlen) still read 0x0000. The parser rejects
            # 'dlen != len(frame) - IP6__HEADER__LEN' (0 != 1).
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b\x00"
            ),
            "_results": {
                "error_message": (
                    "The condition 'dlen == len(self._frame) - IP6__HEADER__LEN' must be met. "
                    "Got: dlen=0, len(self._frame)=41, IP6__HEADER__LEN=40"
                ),
            },
        },
        {
            "_description": "Declared dlen exceeds the frame length (dlen=1, payload absent).",
            # Exactly 40 bytes (no payload) but bytes 4-5 = 0x0001 claim
            # a 1-byte payload. The dlen-vs-frame-length check fires
            # (1 != 0).
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x01\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "error_message": (
                    "The condition 'dlen == len(self._frame) - IP6__HEADER__LEN' must be met. "
                    "Got: dlen=1, len(self._frame)=40, IP6__HEADER__LEN=40"
                ),
            },
        },
    ]
)
class TestIp6ParserIntegrityChecks(TestCase):
    """
    The IPv6 packet parser integrity checks tests.
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

    def test__ip6__parser__integrity_error(self) -> None:
        """
        Ensure the IPv6 packet parser raises Ip6IntegrityError with the
        expected message for each malformed frame.

        Reference: RFC 8200 §3 (IPv6 header integrity — Version / Payload Length).
        """

        with self.assertRaises(Ip6IntegrityError) as error:
            Ip6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][IPv6] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIp6ParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the IPv6 parser integrity validator. These
    exercise the positive path — the shortest frame that passes every
    integrity check — so a future regression that tightens a constraint
    is caught as a test failure rather than silently masked by the
    parametrized rejection fixtures.
    """

    def test__ip6__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a 40-byte frame with ver=6 and dlen=0 passes integrity
        checks and parses successfully.

        Reference: RFC 8200 §3 (IPv6 header integrity — Version / Payload Length).
        """

        self.assertEqual(
            len(_BASELINE_FRAME),
            40,
            msg="Baseline fixture must be exactly IP6__HEADER__LEN bytes.",
        )

        parser = Ip6Parser(PacketRx(_BASELINE_FRAME))

        self.assertEqual(
            parser.dlen,
            0,
            msg="Baseline-frame parser must report dlen=0.",
        )
