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
This module contains tests for the IPv6 Frag packet integrity checks.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__parser__integrity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Ip6FragIntegrityError, Ip6FragParser, IpProto, PacketRx

# Valid 8-byte IPv6 Frag header used by the positive boundary test.
# The parametrized negative fixtures are derived from it by truncation.
#
# IPv6 Frag wire frame (8 bytes, header only):
#   Byte  0     : 0xff       -> next=IpProto.RAW (255)
#   Byte  1     : 0x00       -> reserved (must be zero)
#   Bytes 2-3   : 0x0000     -> offset=0, res=0, flag_mf=0
#   Bytes 4-7   : 0x00000000 -> id=0
_BASELINE_FRAME = b"\xff\x00\x00\x00\x00\x00\x00\x00"


@parameterized_class(
    [
        {
            "_description": "Empty frame (0 bytes).",
            # Zero-byte frame triggers the 'len(frame) < IP6_FRAG__HEADER__LEN'
            # branch before any field is read.
            "_frame_rx": b"",
            "_results": {
                "error_message": (
                    "The condition 'IP6_FRAG__HEADER__LEN <= len(self._frame)' must be met. "
                    "Got: IP6_FRAG__HEADER__LEN=8, len(self._frame)=0"
                ),
            },
        },
        {
            "_description": "Frame is one byte short of IP6_FRAG__HEADER__LEN (7 bytes).",
            # 7-byte fixture: the largest frame that still fails the
            # length check. Anything one byte longer would pass the
            # integrity stage.
            "_frame_rx": b"\xff\x00\x00\x00\x00\x00\x00",
            "_results": {
                "error_message": (
                    "The condition 'IP6_FRAG__HEADER__LEN <= len(self._frame)' must be met. "
                    "Got: IP6_FRAG__HEADER__LEN=8, len(self._frame)=7"
                ),
            },
        },
    ],
)
class TestIp6FragParserIntegrityChecks(TestCase):
    """
    The IPv6 Frag packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IPv6
        layer attributes the Frag parser reads from it.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(self._frame_rx),
        )

    def test__ip6_frag__parser__integrity_error(self) -> None:
        """
        Ensure the IPv6 Frag packet parser raises Ip6FragIntegrityError
        with the expected message for each malformed frame.

        Reference: RFC 8200 §4.5 (Fragment header integrity).
        """

        with self.assertRaises(Ip6FragIntegrityError) as error:
            Ip6FragParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][IPv6 Frag] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIp6FragParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the IPv6 Frag parser integrity validator.
    Exercises the positive path — the shortest frame that passes every
    integrity check — so a future regression that tightens the length
    constraint is caught as a test failure rather than silently masked
    by the parametrized rejection fixtures.
    """

    def test__ip6_frag__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure an 8-byte frame (header only, no payload) passes the
        integrity check and parses successfully.

        Reference: RFC 8200 §4.5 (Fragment header integrity).
        """

        self.assertEqual(
            len(_BASELINE_FRAME),
            8,
            msg="Baseline fixture must be exactly IP6_FRAG__HEADER__LEN bytes.",
        )

        packet_rx = PacketRx(_BASELINE_FRAME)
        packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(_BASELINE_FRAME),
        )

        parser = Ip6FragParser(packet_rx)

        self.assertEqual(
            parser.next,
            IpProto.RAW,
            msg="Baseline-frame parser must report next=IpProto.RAW.",
        )
        self.assertEqual(
            parser.offset,
            0,
            msg="Baseline-frame parser must report offset=0.",
        )
        self.assertFalse(
            parser.flag_mf,
            msg="Baseline-frame parser must report flag_mf=False.",
        )
        self.assertEqual(
            parser.id,
            0,
            msg="Baseline-frame parser must report id=0.",
        )
