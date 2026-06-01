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
Module contains tests for the ICMPv6 ND Router Solicitation message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_solicitation__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)


def _packet_rx_with_ip6(
    frame: bytes,
    *,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub. 'hop' is pinned to 255 and
    'pshdr_sum' to 0 so the ND Router Solicitation integrity and sanity
    checks pass; the caller picks 'src' / 'dst' so each parametrized
    case can steer the unspecified-src vs unicast-src paths.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
            pshdr_sum=0,
            src=ip6__src,
            dst=ip6__dst,
            hop=255,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Router Solicitation message, no options.",
            "_frame_rx": (
                # ICMPv6 Router Solicitation
                #   Type     : 133 (Router Solicitation)
                #   Code     : 0
                #   Checksum : 0x7aff
                #   Reserved : 0x00000000
                #   Options  : none
                b"\x85\x00\x7a\xff\x00\x00\x00\x00"
            ),
            "_ip6__src": Ip6Address("::"),
            "_ip6__dst": Ip6Address("ff02::2"),
            "_results": {
                "message": Icmp6NdMessageRouterSolicitation(
                    cksum=0x7AFF,
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Solicitation message, Slla option present.",
            "_frame_rx": (
                # ICMPv6 Router Solicitation
                #   Type     : 133
                #   Code     : 0
                #   Checksum : 0x1365
                #   Reserved : 0x00000000
                #   Options  : Type 1 (Source Link-Layer Address) = 00:11:22:33:44:55
                b"\x85\x00\x13\x65\x00\x00\x00\x00\x01\x01\x00\x11\x22\x33\x44\x55"
            ),
            "_ip6__src": Ip6Address("2001:db8::1"),
            "_ip6__dst": Ip6Address("ff02::2"),
            "_results": {
                "message": Icmp6NdMessageRouterSolicitation(
                    cksum=0x1365,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
    ]
)
class TestIcmp6NdMessageRouterSolicitationParser(TestCase):
    """
    The ICMPv6 ND Router Solicitation message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _ip6__src: Ip6Address
    _ip6__dst: Ip6Address
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame and IPv6 src/dst pair.
        """

        self._packet_rx = _packet_rx_with_ip6(
            self._frame_rx,
            ip6__src=self._ip6__src,
            ip6__dst=self._ip6__dst,
        )

    def test__icmp6__nd__message__router_solicitation__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6NdMessageRouterSolicitation
        whose fields match the expected reference message for each frame.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__nd__message__router_solicitation__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6NdMessageRouterSolicitation
        instance.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6NdMessageRouterSolicitation,
            msg=f"Parsed message must be Icmp6NdMessageRouterSolicitation for case: {self._description}",
        )

    def test__icmp6__nd__message__router_solicitation__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the parsed
        Router Solicitation message (the whole frame is consumed).

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
