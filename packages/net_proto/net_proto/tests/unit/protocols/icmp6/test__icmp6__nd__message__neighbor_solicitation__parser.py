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
Module contains tests for the ICMPv6 ND Neighbor Solicitation message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_solicitation__parser.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(
    frame: bytes,
    *,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub. 'hop' is pinned to 255 and
    'pshdr_sum' to 0 so the ND Neighbor Solicitation integrity and
    sanity checks pass; the caller picks 'src' / 'dst' so each
    parametrized case can steer the dst-equals-target vs dst-equals-
    solicited-node-multicast paths.
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
            "_description": "ICMPv6 ND Neighbor Solicitation message, no options.",
            "_frame_rx": (
                # ICMPv6 Neighbor Solicitation
                #   Type     : 135 (Neighbor Solicitation)
                #   Code     : 0
                #   Checksum : 0x4b45
                #   Reserved : 0x000000
                #   Target   : 2001:db8::1
                #   Options  : none
                b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ),
            "_ip6__src": Ip6Address("2001:db8::2"),
            "_ip6__dst": Ip6Address("2001:db8::1"),
            "_results": {
                "message": Icmp6NdMessageNeighborSolicitation(
                    cksum=0x4B45,
                    target_address=Ip6Address("2001:db8::1"),
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Solicitation message, Slla option present.",
            "_frame_rx": (
                # ICMPv6 Neighbor Solicitation
                #   Type     : 135
                #   Code     : 0
                #   Checksum : 0xe3a9
                #   Reserved : 0x000000
                #   Target   : 2001:db8::2
                #   Options  : Type 1 (Source Link-Layer Address) = 00:11:22:33:44:55
                b"\x87\x00\xe3\xa9\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
            ),
            "_ip6__src": Ip6Address("2001:db8::1"),
            "_ip6__dst": Ip6Address("2001:db8::2"),
            "_results": {
                "message": Icmp6NdMessageNeighborSolicitation(
                    cksum=0xE3A9,
                    target_address=Ip6Address("2001:db8::2"),
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
    ]
)
class TestIcmp6NdMessageNeighborSolicitationParser(TestCase):
    """
    The ICMPv6 ND Neighbor Solicitation message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _ip6__src: Ip6Address
    _ip6__dst: Ip6Address
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame and IPv6 src/dst pair.
        """

        self._packet_rx = _packet_rx_with_ip6(
            self._frame_rx,
            ip6__src=self._ip6__src,
            ip6__dst=self._ip6__dst,
        )

    def test__icmp6__nd__message__neighbor_solicitation__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6NdMessageNeighborSolicitation
        whose fields match the expected reference message for each frame.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_solicitation__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6NdMessageNeighborSolicitation
        instance.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6NdMessageNeighborSolicitation,
            msg=f"Parsed message must be Icmp6NdMessageNeighborSolicitation for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_solicitation__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the parsed
        Neighbor Solicitation message (the whole frame is consumed).

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
