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
Module contains tests for the ICMPv6 ND Neighbor Advertisement message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_advertisement__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)


def _packet_rx_with_ip6(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub. 'hop' is set to 255, 'src'
    to a unicast address, and 'dst' to all-nodes multicast so the ND
    Neighbor Advertisement sanity checks pass regardless of the
    'flag_s' value in the frame.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
            pshdr_sum=0,
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("ff02::1"),
            hop=255,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, no options.",
            "_frame_rx": (
                # ICMPv6 Neighbor Advertisement
                #   Type     : 136 (Neighbor Advertisement)
                #   Code     : 0
                #   Checksum : 0xaa44
                #   Flags    : 0xa0 (R=1, S=0, O=1)
                #   Reserved : 0x000000
                #   Target   : 2001:db8::1
                #   Options  : none
                b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ),
            "_results": {
                "message": Icmp6NdMessageNeighborAdvertisement(
                    cksum=0xAA44,
                    flag_r=True,
                    flag_s=False,
                    flag_o=True,
                    target_address=Ip6Address("2001:db8::1"),
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, Slla option present.",
            "_frame_rx": (
                # ICMPv6 Neighbor Advertisement
                #   Type     : 136
                #   Code     : 0
                #   Checksum : 0xa2a9
                #   Flags    : 0x40 (R=0, S=1, O=0)
                #   Reserved : 0x000000
                #   Target   : 2001:db8::2
                #   Options  : Type 1 (Source Link-Layer Address) = 00:11:22:33:44:55
                b"\x88\x00\xa2\xa9\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
            ),
            "_results": {
                "message": Icmp6NdMessageNeighborAdvertisement(
                    cksum=0xA2A9,
                    flag_r=False,
                    flag_s=True,
                    flag_o=False,
                    target_address=Ip6Address("2001:db8::2"),
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
    ]
)
class TestIcmp6NdMessageNeighborAdvertisementParser(TestCase):
    """
    The ICMPv6 ND Neighbor Advertisement message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx)

    def test__icmp6__nd__message__neighbor_advertisement__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6NdMessageNeighborAdvertisement
        whose fields match the expected reference message for each frame.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6NdMessageNeighborAdvertisement
        instance.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6NdMessageNeighborAdvertisement,
            msg=f"Parsed message must be Icmp6NdMessageNeighborAdvertisement for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the parsed
        Neighbor Advertisement message (the whole frame is consumed).

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
