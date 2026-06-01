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
This module contains tests for the IGMP message 'type' enum.

net_proto/tests/unit/protocols/igmp/test__igmp__message__enums.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.protocols.igmp.message.igmp__message import IgmpType


@parameterized_class(
    [
        {
            "_description": "IgmpType.MEMBERSHIP_QUERY known value.",
            "_member": IgmpType.MEMBERSHIP_QUERY,
            "_results": {"value": 0x11},
        },
        {
            "_description": "IgmpType.V1_MEMBERSHIP_REPORT known value.",
            "_member": IgmpType.V1_MEMBERSHIP_REPORT,
            "_results": {"value": 0x12},
        },
        {
            "_description": "IgmpType.V2_MEMBERSHIP_REPORT known value.",
            "_member": IgmpType.V2_MEMBERSHIP_REPORT,
            "_results": {"value": 0x16},
        },
        {
            "_description": "IgmpType.V2_LEAVE_GROUP known value.",
            "_member": IgmpType.V2_LEAVE_GROUP,
            "_results": {"value": 0x17},
        },
        {
            "_description": "IgmpType.V3_MEMBERSHIP_REPORT known value.",
            "_member": IgmpType.V3_MEMBERSHIP_REPORT,
            "_results": {"value": 0x22},
        },
    ]
)
class TestIgmpMessageTypeKnown(TestCase):
    """
    The IGMP message 'type' enum known-value tests.
    """

    _description: str
    _member: IgmpType
    _results: dict[str, Any]

    def test__igmp__message__type__value(self) -> None:
        """
        Ensure each known IgmpType member maps to its documented numeric value.

        Reference: RFC 3376 §4 (IGMP message types 0x11 / 0x22).
        Reference: RFC 2236 §2.1 (IGMPv2 message types 0x16 / 0x17).
        Reference: RFC 1112 §6 (IGMPv1 Membership Report type 0x12).
        """

        self.assertEqual(
            self._member.value,
            self._results["value"],
            msg=f"{self._description}: wrong numeric value.",
        )

    def test__igmp__message__type__is_unknown_false(self) -> None:
        """
        Ensure known IgmpType members report 'is_unknown' as False.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._member.is_unknown,
            msg=f"{self._description}: must not be flagged as unknown.",
        )

    def test__igmp__message__type__bytes_is_one_byte(self) -> None:
        """
        Ensure the IgmpType serializes to a single byte.

        Reference: RFC 3376 §4 (the 'type' field is a single octet).
        """

        self.assertEqual(
            bytes(self._member),
            int(self._member.value).to_bytes(1, "big"),
            msg=f"{self._description}: wrong byte representation.",
        )

    def test__igmp__message__type__from_int_roundtrip(self) -> None:
        """
        Ensure 'from_int(value)' resolves back to the typed member.

        Reference: RFC 3376 §4 (the 'type' field discriminates the message).
        """

        self.assertIs(
            IgmpType.from_int(self._results["value"]),
            self._member,
            msg=f"{self._description}: from_int did not resolve the typed member.",
        )


class TestIgmpMessageTypeUnknown(TestCase):
    """
    The IGMP message 'type' enum unknown-value tests.
    """

    def test__igmp__message__type__unknown_registers_as_member(self) -> None:
        """
        Ensure an unrecognised IGMP type byte materialises a cached
        'UNKNOWN_<value>' member so the RX dispatch can silently ignore
        it rather than raising.

        Reference: RFC 3376 §4 (unrecognized message types MUST be silently ignored).
        """

        unknown = IgmpType.from_int(0x99)

        self.assertEqual(unknown.value, 0x99)
        self.assertTrue(unknown.is_unknown)
