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
Module contains tests for the ICMPv6 ND Recursive DNS Server (RDNSS)
option per RFC 8106 §5.1.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__rdnss.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6IntegrityError,
    Icmp6NdOptionRdnss,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Single RDNSS (length=3, 24 bytes total).",
            "_kwargs": {
                "lifetime": 3600,
                "addresses": (Ip6Address("2001:db8::1"),),
            },
            "_results": {
                "__len__": 24,
                "__bytes__": (
                    # Type=25, Length=3, Reserved=0, Lifetime=3600, Address.
                    b"\x19\x03\x00\x00\x00\x00\x0e\x10"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "__str__": "rdnss (lifetime 3600, servers [2001:db8::1])",
            },
        },
        {
            "_description": "Two RDNSS (length=5, 40 bytes total).",
            "_kwargs": {
                "lifetime": 7200,
                "addresses": (
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                ),
            },
            "_results": {
                "__len__": 40,
                "__bytes__": (
                    # Type=25, Length=5, Reserved=0, Lifetime=7200.
                    b"\x19\x05\x00\x00\x00\x00\x1c\x20"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                ),
                "__str__": "rdnss (lifetime 7200, servers [2001:db8::1, 2001:db8::2])",
            },
        },
        {
            "_description": "Lifetime=0 (drop signal, RFC 8106 §5.1).",
            "_kwargs": {
                "lifetime": 0,
                "addresses": (Ip6Address("fe80::1"),),
            },
            "_results": {
                "__len__": 24,
                "__bytes__": (
                    b"\x19\x03\x00\x00\x00\x00\x00\x00"
                    b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "__str__": "rdnss (lifetime 0, servers [fe80::1])",
            },
        },
    ]
)
class TestIcmp6NdOptionRdnssAssembler(TestCase):
    """
    The ICMPv6 ND Recursive DNS Server option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the option from _kwargs.
        """

        self._option = Icmp6NdOptionRdnss(**self._kwargs)

    def test__icmp6__nd__option__rdnss__len(self) -> None:
        """
        Ensure '__len__' returns the on-wire byte length.

        Reference: RFC 8106 §5.1 (RDNSS option byte length).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__rdnss__bytes(self) -> None:
        """
        Ensure '__bytes__' produces the expected wire encoding.

        Reference: RFC 8106 §5.1 (RDNSS wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__rdnss__str(self) -> None:
        """
        Ensure '__str__' produces the canonical log representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Single RDNSS (length=3, 24 bytes total).",
            "_frame": (
                b"\x19\x03\x00\x00\x00\x00\x0e\x10" b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
            ),
            "_results": {
                "lifetime": 3600,
                "addresses": (Ip6Address("2001:db8::1"),),
            },
        },
        {
            "_description": "Two RDNSS (length=5, 40 bytes total).",
            "_frame": (
                b"\x19\x05\x00\x00\x00\x00\x1c\x20"
                b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_results": {
                "lifetime": 7200,
                "addresses": (
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                ),
            },
        },
        {
            "_description": "Header-only (length=1, no addresses).",
            "_frame": b"\x19\x01\x00\x00\x00\x00\x0e\x10",
            "_results": {
                "lifetime": 3600,
                "addresses": (),
            },
        },
    ]
)
class TestIcmp6NdOptionRdnssParser(TestCase):
    """
    The ICMPv6 ND Recursive DNS Server option parser tests.
    """

    _description: str
    _frame: bytes
    _results: dict[str, Any]

    def test__icmp6__nd__option__rdnss__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' decodes the on-wire bytes into the
        expected dataclass.

        Reference: RFC 8106 §5.1 (RDNSS wire format).
        """

        option = Icmp6NdOptionRdnss.from_buffer(self._frame)

        self.assertEqual(
            option.lifetime,
            self._results["lifetime"],
            msg=f"Unexpected lifetime for case: {self._description}",
        )
        self.assertEqual(
            option.addresses,
            self._results["addresses"],
            msg=f"Unexpected addresses for case: {self._description}",
        )


class TestIcmp6NdOptionRdnssIntegrity(TestCase):
    """
    Integrity-check rejection cases for the RDNSS option parser.
    """

    def test__icmp6__nd__option__rdnss__from_buffer__even_length_rejected(self) -> None:
        """
        Ensure a length-field of 2 (an even value, which would
        imply a non-integer address count) is rejected as an
        integrity violation.

        Reference: RFC 8106 §5.1 (length = 1 + 2 * address_count).
        """

        # Length=2 → 16 bytes total, but length-1=1 isn't divisible
        # by 2 — invalid encoding.
        bad = b"\x19\x02\x00\x00\x00\x00\x0e\x10\x00\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6NdOptionRdnss.from_buffer(bad)
