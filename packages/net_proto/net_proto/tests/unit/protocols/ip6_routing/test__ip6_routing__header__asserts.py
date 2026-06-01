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
This module contains the IPv6 Routing header dataclass __post_init__ asserts.

net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__header__asserts.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.lib.enums import IpProto
from net_proto.lib.int_checks import UINT_8__MAX
from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType
from net_proto.protocols.ip6_routing.ip6_routing__header import (
    IP6_ROUTING__HEADER__LEN,
    Ip6RoutingHeader,
)


class TestIp6RoutingHeaderAsserts(TestCase):
    """
    The IPv6 Routing header constructor invariant tests.
    """

    def test__ip6_routing__header__defaults_accepted(self) -> None:
        """
        Ensure a minimum valid header (next=RAW, hdr_ext_len=0,
        routing_type=RH4, segments_left=0) constructs cleanly.

        Reference: RFC 8200 §4.4 (Routing Header fixed 4-byte prefix).
        """

        header = Ip6RoutingHeader(
            next=IpProto.RAW,
            hdr_ext_len=0,
            routing_type=Ip6RoutingType.RH4,
            segments_left=0,
        )
        self.assertEqual(
            len(header),
            IP6_ROUTING__HEADER__LEN,
            msg="Default Ip6RoutingHeader must report fixed 4-byte prefix length.",
        )

    def test__ip6_routing__header__rejects_non_ipproto_next(self) -> None:
        """
        Ensure passing a non-IpProto value to 'next' trips the
        dataclass __post_init__ assert.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6RoutingHeader(
                next=6,  # type: ignore[arg-type]
                hdr_ext_len=0,
                routing_type=Ip6RoutingType.RH4,
                segments_left=0,
            )

    def test__ip6_routing__header__rejects_overflow_hdr_ext_len(self) -> None:
        """
        Ensure 'hdr_ext_len' rejects values above the uint8 ceiling.

        Reference: RFC 8200 §4.4 (Hdr Ext Len 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6RoutingHeader(
                next=IpProto.RAW,
                hdr_ext_len=UINT_8__MAX + 1,
                routing_type=Ip6RoutingType.RH4,
                segments_left=0,
            )

    def test__ip6_routing__header__rejects_overflow_segments_left(self) -> None:
        """
        Ensure 'segments_left' rejects values above the uint8 ceiling.

        Reference: RFC 8200 §4.4 (Segments Left 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6RoutingHeader(
                next=IpProto.RAW,
                hdr_ext_len=0,
                routing_type=Ip6RoutingType.RH4,
                segments_left=UINT_8__MAX + 1,
            )

    def test__ip6_routing__header__rejects_non_routing_type(self) -> None:
        """
        Ensure passing a non-Ip6RoutingType value to 'routing_type'
        trips the dataclass assert.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6RoutingHeader(
                next=IpProto.RAW,
                hdr_ext_len=0,
                routing_type=4,  # type: ignore[arg-type]
                segments_left=0,
            )

    def test__ip6_routing__header__bytes_round_trip(self) -> None:
        """
        Ensure 'from_buffer(bytes(hdr)) == hdr' — header round-trip
        identity for the four wire fields.

        Reference: RFC 8200 §4.4 (Routing Header wire format).
        """

        original = Ip6RoutingHeader(
            next=IpProto.TCP,
            hdr_ext_len=2,
            routing_type=Ip6RoutingType.RH4,
            segments_left=3,
        )
        recovered = Ip6RoutingHeader.from_buffer(bytes(original))
        self.assertEqual(
            recovered,
            original,
            msg="Header round-trip from_buffer must equal original.",
        )
