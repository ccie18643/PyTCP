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
Module contains tests for the ICMPv6 ND Router Advertisement message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_advertisement__parser.py

ver 3.0.10
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address, Ip6Network, MacAddress
from net_proto import (
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptionPi,
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
    'pshdr_sum' to 0 so the ND Router Advertisement integrity and sanity
    checks pass; the caller picks 'src' / 'dst' so each parametrized case
    can steer the unicast vs all-nodes-multicast dst paths.
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
            "_description": "ICMPv6 ND Router Advertisement message, no options.",
            "_frame_rx": (
                # ICMPv6 Router Advertisement
                #   Type             : 134 (Router Advertisement)
                #   Code             : 0
                #   Checksum         : 0x7a3e
                #   Hop Limit        : 255
                #   Flags            : 0xc0 (M=1, O=1)
                #   Router Lifetime  : 0xffff
                #   Reachable Time   : 0xffffffff
                #   Retrans Timer    : 0xffffffff
                #   Options          : none
                b"\x86\x00\x7a\x3e\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
            "_ip6__src": Ip6Address("fe80::1"),
            "_ip6__dst": Ip6Address("ff02::1"),
            "_results": {
                "message": Icmp6NdMessageRouterAdvertisement(
                    cksum=0x7A3E,
                    hop=255,
                    flag_m=True,
                    flag_o=True,
                    router_lifetime=65535,
                    reachable_time=4294967295,
                    retrans_timer=4294967295,
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla option present.",
            "_frame_rx": (
                # ICMPv6 Router Advertisement
                #   Type             : 134
                #   Code             : 0
                #   Checksum         : 0xcd0c
                #   Hop Limit        : 64
                #   Flags            : 0x00
                #   Router Lifetime  : 123
                #   Reachable Time   : 456
                #   Retrans Timer    : 789
                #   Options          : Type 1 (Source Link-Layer Address) = 00:11:22:33:44:55
                b"\x86\x00\xcd\x0c\x40\x00\x00\x7b\x00\x00\x01\xc8\x00\x00\x03\x15"
                b"\x01\x01\x00\x11\x22\x33\x44\x55"
            ),
            "_ip6__src": Ip6Address("fe80::1"),
            "_ip6__dst": Ip6Address("ff02::1"),
            "_results": {
                "message": Icmp6NdMessageRouterAdvertisement(
                    cksum=0xCD0C,
                    hop=64,
                    flag_m=False,
                    flag_o=False,
                    router_lifetime=123,
                    reachable_time=456,
                    retrans_timer=789,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla & Pi options present.",
            "_frame_rx": (
                # ICMPv6 Router Advertisement
                #   Type             : 134
                #   Code             : 0
                #   Checksum         : 0xab86
                #   Hop Limit        : 22
                #   Flags            : 0x80 (M=1)
                #   Router Lifetime  : 33
                #   Reachable Time   : 44
                #   Retrans Timer    : 55
                #   Options          : Type 1 (SLLA) = 00:11:22:33:44:55;
                #                      Type 3 (PI)   prefix=2001:db8::/64,
                #                                    vlft=123456, plft=654321,
                #                                    L=1, A=1, R=1
                b"\x86\x00\xab\x86\x16\x80\x00\x21\x00\x00\x00\x2c\x00\x00\x00\x37"
                b"\x01\x01\x00\x11\x22\x33\x44\x55\x03\x04\x40\xe0\x00\x01\xe2\x40"
                b"\x00\x09\xfb\xf1\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            "_ip6__src": Ip6Address("fe80::1"),
            "_ip6__dst": Ip6Address("2001:db8::1"),
            "_results": {
                "message": Icmp6NdMessageRouterAdvertisement(
                    cksum=0xAB86,
                    hop=22,
                    flag_m=True,
                    flag_o=False,
                    router_lifetime=33,
                    reachable_time=44,
                    retrans_timer=55,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                        Icmp6NdOptionPi(
                            prefix=Ip6Network("2001:db8::/64"),
                            valid_lifetime=123456,
                            preferred_lifetime=654321,
                            flag_l=True,
                            flag_a=True,
                            flag_r=True,
                        ),
                    ),
                ),
            },
        },
    ]
)
class TestIcmp6NdMessageRouterAdvertisementParser(TestCase):
    """
    The ICMPv6 ND Router Advertisement message parser tests.
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

    def test__icmp6__nd__message__router_advertisement__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6NdMessageRouterAdvertisement
        whose fields match the expected reference message for each frame.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6NdMessageRouterAdvertisement
        instance.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6NdMessageRouterAdvertisement,
            msg=f"Parsed message must be Icmp6NdMessageRouterAdvertisement for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the parsed
        Router Advertisement message (the whole frame is consumed).

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
