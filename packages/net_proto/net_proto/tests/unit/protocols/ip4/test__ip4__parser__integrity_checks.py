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
This module contains tests for the IPv4 packet integrity checks.

net_proto/tests/unit/protocols/ip4/test__ip4__parser__integrity_checks.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Ip4IntegrityError, Ip4Parser, PacketRx

# Valid 20-byte IPv4 frame used by the positive boundary test.
# ver=4, hlen=20, dscp=63, ecn=3, plen=20, id=65535, flag_df=1,
# ttl=255, proto=RAW, cksum=0xd923, src=10.20.30.40, dst=50.60.70.80.
_BASELINE_FRAME = b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"


@parameterized_class(
    [
        {
            "_description": "Frame shorter than IP4__HEADER__LEN (19 bytes).",
            # ver=4, hlen=20 declared by byte 0, plen=20 declared by bytes
            # 2-3, but the frame is truncated to 19 bytes so the
            # 'len(frame) < IP4__HEADER__LEN' branch of _validate_integrity
            # fires first.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x73\x0a\x14\x1e\x28" b"\x32\x3c\x46"),
            "_results": {
                "error_message": (
                    "The condition 'IP4__HEADER__LEN <= len(self._frame)' must be met. "
                    "Got: IP4__HEADER__LEN=20, len(self._frame)=19"
                ),
            },
        },
        {
            "_description": "Version field is not 4.",
            # Byte 0 = 0x55 encodes ver=5, hlen=5*4=20. The parser
            # rejects any ver != 4 before evaluating hlen/plen.
            "_frame_rx": (b"\x55\xff\x00\x14\xff\xff\x40\x00\xff\xff\xc9\x23\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "The 'ver' field must be 4. Got: 5",
            },
        },
        {
            "_description": "Decoded hlen is below IP4__HEADER__LEN (hlen=16).",
            # Byte 0 = 0x44 encodes ver=4, hlen=4*4=16, below the 20-byte
            # minimum required by 'IP4__HEADER__LEN <= hlen'.
            "_frame_rx": (b"\x44\xff\x00\x14\xff\xff\x40\x00\xff\xff\xda\x23\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50"),
            "_results": {
                "error_message": (
                    "The condition 'IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)' "
                    "must be met. Got: IP4__HEADER__LEN=20, hlen=16, plen=20, len(self._frame)=20"
                ),
            },
        },
        {
            "_description": "plen is below hlen (plen=19, hlen=20).",
            # Byte 0 = 0x45 -> hlen=20. Bytes 2-3 = 0x0013 -> plen=19,
            # violating the 'hlen <= plen' constraint.
            "_frame_rx": (b"\x45\xff\x00\x13\xff\xff\x40\x00\xff\xff\xd9\x24\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50"),
            "_results": {
                "error_message": (
                    "The condition 'IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)' "
                    "must be met. Got: IP4__HEADER__LEN=20, hlen=20, plen=19, len(self._frame)=20"
                ),
            },
        },
        {
            "_description": "Declared hlen/plen exceed the frame length.",
            # Byte 0 = 0x46 -> hlen=24. Bytes 2-3 = 0x0018 -> plen=24.
            # The frame itself is only 20 bytes so 'plen <= len(frame)'
            # fails.
            "_frame_rx": (b"\x46\xff\x00\x18\xff\xff\x40\x00\xff\xff\xd8\x1f\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50"),
            "_results": {
                "error_message": (
                    "The condition 'IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)' "
                    "must be met. Got: IP4__HEADER__LEN=20, hlen=24, plen=24, len(self._frame)=20"
                ),
            },
        },
        {
            "_description": "Header checksum is invalid.",
            # Identical to the baseline frame but with bytes 10-11
            # (the cksum field) flipped from 0xd923 to 0xd924 so
            # 'inet_cksum(self._frame[:hlen])' returns non-zero.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x24\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
        {
            "_description": "IPv4 option declares length below the 2-byte minimum.",
            # 24-byte frame: valid 20-byte header + one options byte
            # pair (type=0xff, len=0x01) + two 0x00 padding bytes.
            # Ip4Options.validate_integrity rejects len < 2.
            "_frame_rx": (
                b"\x46\xff\x00\x18\xff\xff\x40\x00\xff\xff\xd9\x1d\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50\xff\x01\x00\x00"
            ),
            "_results": {
                "error_message": "The IPv4 option length must be greater than 1. Got: 1.",
            },
        },
        {
            "_description": "IPv4 option declares length that overruns hlen.",
            # 24-byte frame: valid 20-byte header + one options byte
            # pair (type=0xff, len=0x05) + two 0x00 padding bytes.
            # With hlen=24, advancing from offset=20 by len=5 reaches
            # offset=25 > 24.
            "_frame_rx": (
                b"\x46\xff\x00\x18\xff\xff\x40\x00\xff\xff\xd9\x19\x0a\x14\x1e\x28" b"\x32\x3c\x46\x50\xff\x05\x00\x00"
            ),
            "_results": {
                "error_message": (
                    "The IPv4 option length must not extend past the header length. " "Got: offset=25, hlen=24"
                ),
            },
        },
    ]
)
class TestIp4ParserIntegrityChecks(TestCase):
    """
    The IPv4 packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx so it can be fed to
        Ip4Parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__ip4__parser__integrity_error(self) -> None:
        """
        Ensure the IPv4 packet parser raises Ip4IntegrityError with the
        expected message for each malformed frame.

        Reference: RFC 791 §3.1 (IPv4 header integrity — IHL / Total Length).
        """

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][IPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIp4ParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the IPv4 parser integrity validator. These
    exercise the positive path — the shortest frame that passes every
    integrity check — so a future regression that tightens a constraint
    is caught as a test failure rather than silently masked by the
    parametrized rejection fixtures.
    """

    def test__ip4__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a 20-byte frame with hlen=plen=20 and a valid checksum
        passes integrity checks and parses successfully.

        Reference: RFC 791 §3.1 (IPv4 header integrity — IHL / Total Length).
        """

        self.assertEqual(
            len(_BASELINE_FRAME),
            20,
            msg="Baseline fixture must be exactly IP4__HEADER__LEN bytes.",
        )

        parser = Ip4Parser(PacketRx(_BASELINE_FRAME))

        self.assertEqual(
            parser.hlen,
            20,
            msg="Baseline-frame parser must report hlen=20.",
        )
        self.assertEqual(
            parser.plen,
            20,
            msg="Baseline-frame parser must report plen=20.",
        )
