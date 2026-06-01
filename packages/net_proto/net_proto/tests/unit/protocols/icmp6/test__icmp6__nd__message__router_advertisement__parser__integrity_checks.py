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
Module contains tests for the ICMPv6 ND Router Advertisement message parser
integrity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_advertisement__parser__integrity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address
from net_proto import (
    ICMP6__ND__ROUTER_ADVERTISEMENT__LEN,
    Icmp6IntegrityError,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)

# Valid 16-byte RA, hop=64, flags=0, router_lifetime=0xffff, reachable_time=0,
# retrans_timer=0 — used as a baseline for the positive boundary test.
# Checksum 0x39ff with pshdr_sum=0.
_RA_BASELINE_FRAME = b"\x86\x00\x39\xff\x40\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"


def _packet_rx_with_ip6(
    frame: bytes,
    *,
    ip6__dlen: int | None = None,
    ip6__hop: int = 255,
) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6'. 'ip6__hop' defaults to 255 and
    'src' is pinned to a link-local address so RA sanity rules pass on the
    positive boundary path.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame) if ip6__dlen is None else ip6__dlen,
            payload_len=len(frame) if ip6__dlen is None else ip6__dlen,
            pshdr_sum=0,
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            hop=ip6__hop,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": (
                "ICMPv6 ND Router Advertisement, the 'ICMP6__HEADER__LEN <= self._ip6__dlen' "
                "condition not met (frame shorter than ICMPv6 base header)."
            ),
            "_frame_rx": (
                # ICMPv6 Router Advertisement (truncated, < 4 bytes)
                #   Type     : 134 (Router Advertisement)
                #   Code     : 0
                #   Checksum : 0x00-- (missing low byte)
                #   Frame len: 3 bytes
                b"\x86\x00\x00"
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
                "ICMPv6 ND Router Advertisement, the 'self._ip6__dlen <= len(self._frame)' "
                "condition not met (declared IPv6 payload exceeds frame length)."
            ),
            "_frame_rx": (
                # ICMPv6 Router Advertisement
                #   Type     : 134
                #   Code     : 0
                #   Checksum : 0x0000 (placeholder)
                #   Hop      : 0xff
                #   Flags    : 0xc0 (M=1, O=1)
                #   Router lifetime/reachable/retrans : 0xffff / -- / --
                #   Frame len: 15 bytes (< declared ip6__dlen=16)
                b"\x86\x00\x00\x00\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
            "_ip6__dlen": 16,
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=16, len(self._frame)=15"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 ND Router Advertisement, the "
                "'ICMP6__ND__ROUTER_ADVERTISEMENT__LEN <= ip6__dlen' "
                "condition not met (payload shorter than Router Advertisement fixed size)."
            ),
            "_frame_rx": (
                # ICMPv6 Router Advertisement (15 bytes, below the 16-byte minimum)
                b"\x86\x00\x00\x00\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
            "_ip6__dlen": 15,
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__ND__ROUTER_ADVERTISEMENT__LEN <= ip6__dlen "
                    "<= len(frame)' must be met. Got: ICMP6__ND__ROUTER_ADVERTISEMENT__LEN=16, "
                    "ip6__dlen=15, len(frame)=15"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement with invalid checksum (all-0xff).",
            "_frame_rx": (
                # ICMPv6 Router Advertisement (16 bytes, checksum 0x0000 against a
                # non-zero payload, so the computed checksum will not validate).
                b"\x86\x00\x00\x00\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
            "_ip6__dlen": None,
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp6NdMessageRouterAdvertisementParserIntegrityChecks(TestCase):
    """
    The ICMPv6 ND Router Advertisement message parser integrity checks tests.
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

    def test__icmp6__nd__message__router_advertisement__parser__integrity_error(self) -> None:
        """
        Ensure the ICMPv6 parser raises Icmp6IntegrityError on malformed
        Router Advertisement frames with the expected message.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv6] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp6NdMessageRouterAdvertisementParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv6 ND Router Advertisement integrity validator.
    """

    def test__icmp6__nd__message__router_advertisement__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame whose IPv6 payload length equals
        ICMP6__ND__ROUTER_ADVERTISEMENT__LEN (16) — a bare RA with no
        options — passes integrity checks and parses successfully.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            len(_RA_BASELINE_FRAME),
            ICMP6__ND__ROUTER_ADVERTISEMENT__LEN,
            msg="Baseline fixture must match ICMP6__ND__ROUTER_ADVERTISEMENT__LEN.",
        )

        Icmp6Parser(_packet_rx_with_ip6(_RA_BASELINE_FRAME))
