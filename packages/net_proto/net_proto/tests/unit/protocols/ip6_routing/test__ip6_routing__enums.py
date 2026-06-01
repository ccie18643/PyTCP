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
This module contains tests for the IPv6 Routing Header enums.

net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__enums.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType


@parameterized_class(
    [
        {
            "_description": "Ip6RoutingType.RH0 (deprecated by RFC 5095).",
            "_member": Ip6RoutingType.RH0,
            "_results": {"value": 0, "__str__": "RH0"},
        },
        {
            "_description": "Ip6RoutingType.RH2 (mobility, RFC 6275).",
            "_member": Ip6RoutingType.RH2,
            "_results": {"value": 2, "__str__": "RH2"},
        },
        {
            "_description": "Ip6RoutingType.RH3 (RPL, RFC 6554).",
            "_member": Ip6RoutingType.RH3,
            "_results": {"value": 3, "__str__": "RH3"},
        },
        {
            "_description": "Ip6RoutingType.RH4 (Segment Routing, RFC 8754).",
            "_member": Ip6RoutingType.RH4,
            "_results": {"value": 4, "__str__": "RH4"},
        },
    ]
)
class TestIp6RoutingTypeKnown(TestCase):
    """
    The Ip6RoutingType known-value tests.
    """

    _description: str
    _member: Ip6RoutingType
    _results: dict[str, Any]

    def test__ip6_routing__enums__type__value(self) -> None:
        """
        Ensure each known Ip6RoutingType member maps to its IANA-
        assigned numeric value.

        Reference: RFC 8200 §4.4 (Routing Type field, IANA registry).
        """

        self.assertEqual(
            self._member.value,
            self._results["value"],
            msg=f"{self._description}: wrong numeric value.",
        )

    def test__ip6_routing__enums__type__str(self) -> None:
        """
        Ensure each known Ip6RoutingType member renders to its
        canonical short name.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._member),
            self._results["__str__"],
            msg=f"{self._description}: wrong string label.",
        )


class TestIp6RoutingTypeUnknown(TestCase):
    """
    The Ip6RoutingType unknown-value tests.
    """

    def test__ip6_routing__enums__type__unknown_registers_as_member(self) -> None:
        """
        Ensure 'from_int' on an unknown value (e.g. an unassigned
        routing type) dynamically extends the enum and reports
        'is_unknown=True', so the parser preserves the original
        wire value for Phase-2 forwarder re-emission.

        Reference: RFC 8200 §4.4 (unrecognized Routing Type
                preservation for forwarders).
        """

        unknown = Ip6RoutingType.from_int(99)
        self.assertEqual(unknown.value, 99, msg="from_int(99) must yield value 99.")
        self.assertTrue(unknown.is_unknown, msg="from_int(99) must report is_unknown=True.")
