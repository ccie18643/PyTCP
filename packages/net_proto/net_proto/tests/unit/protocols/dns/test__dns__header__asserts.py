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
This module contains tests for the DNS header field assertions.

net_proto/tests/unit/protocols/dns/test__dns__header__asserts.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from net_proto.protocols.dns.dns__enums import DnsOpcode, DnsResponseCode
from net_proto.protocols.dns.dns__header import (
    DNS__HEADER__LEN,
    DnsHeader,
)

_VALID_KWARGS: dict[str, Any] = {
    "id": 0x1234,
    "qr": False,
    "opcode": DnsOpcode.QUERY,
    "aa": False,
    "tc": False,
    "rd": True,
    "ra": False,
    "z": 0,
    "rcode": DnsResponseCode.NOERROR,
    "qdcount": 1,
    "ancount": 0,
    "nscount": 0,
    "arcount": 0,
}


class TestDnsHeaderAccepted(TestCase):
    """
    The DNS header accepted-construction and wire-format tests.
    """

    def test__dns__header__default_accepted(self) -> None:
        """
        Ensure a minimal valid set of DNS header field values constructs a
        12-octet header.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        self.assertEqual(
            len(DnsHeader(**_VALID_KWARGS)),
            DNS__HEADER__LEN,
            msg="A valid DNS header must be 12 octets long.",
        )

    def test__dns__header__buffer_round_trip(self) -> None:
        """
        Ensure a DNS header serializes to its 12-octet wire form and parses
        back to an equal header, with the flag word packed in the canonical
        bit layout.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        header = DnsHeader(**_VALID_KWARGS)

        # id=0x1234; flags: qr=0, opcode=0, aa/tc=0, rd=1 -> 0x0100;
        # qdcount=1; ancount/nscount/arcount=0.
        self.assertEqual(
            bytes(header),
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
            msg="The DNS header must serialize with the flag word packed per RFC 1035.",
        )
        self.assertEqual(
            DnsHeader.from_buffer(bytes(header)),
            header,
            msg="A DNS header must parse back to an equal header.",
        )


@parameterized_class(
    [
        {
            "_description": "The 'id' field below the minimum.",
            "_override": {"id": UINT_16__MIN - 1},
            "_error_fragment": "The 'id' field must be a 16-bit unsigned integer.",
        },
        {
            "_description": "The 'id' field above the maximum.",
            "_override": {"id": UINT_16__MAX + 1},
            "_error_fragment": "The 'id' field must be a 16-bit unsigned integer.",
        },
        {
            "_description": "The 'qr' field not a boolean.",
            "_override": {"qr": 1},
            "_error_fragment": "The 'qr' field must be a boolean.",
        },
        {
            "_description": "The 'opcode' field not a DnsOpcode.",
            "_override": {"opcode": 0},
            "_error_fragment": "The 'opcode' field must be a DnsOpcode.",
        },
        {
            "_description": "The 'rd' field not a boolean.",
            "_override": {"rd": 1},
            "_error_fragment": "The 'rd' field must be a boolean.",
        },
        {
            "_description": "The 'z' field above the 3-bit maximum.",
            "_override": {"z": 8},
            "_error_fragment": "The 'z' field must be a 3-bit unsigned integer.",
        },
        {
            "_description": "The 'rcode' field not a DnsResponseCode.",
            "_override": {"rcode": 0},
            "_error_fragment": "The 'rcode' field must be a DnsResponseCode.",
        },
        {
            "_description": "The 'qdcount' field above the maximum.",
            "_override": {"qdcount": UINT_16__MAX + 1},
            "_error_fragment": "The 'qdcount' field must be a 16-bit unsigned integer.",
        },
        {
            "_description": "The 'ancount' field below the minimum.",
            "_override": {"ancount": UINT_16__MIN - 1},
            "_error_fragment": "The 'ancount' field must be a 16-bit unsigned integer.",
        },
    ]
)
class TestDnsHeaderRejected(TestCase):
    """
    The DNS header rejected-construction tests.
    """

    _description: str
    _override: dict[str, Any]
    _error_fragment: str

    def test__dns__header__rejects_invalid_field(self) -> None:
        """
        Ensure constructing a DNS header with an out-of-range or wrongly
        typed field is rejected by the header field assertions.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        with self.assertRaises(AssertionError) as raised:
            DnsHeader(**(_VALID_KWARGS | self._override))

        self.assertIn(
            self._error_fragment,
            str(raised.exception),
            msg=f"Unexpected assertion message for case: {self._description}",
        )
