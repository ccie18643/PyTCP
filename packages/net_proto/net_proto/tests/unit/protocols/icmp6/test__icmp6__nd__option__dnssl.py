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
Module contains tests for the ICMPv6 ND DNS Search List (DNSSL)
option per RFC 8106 §5.2.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__dnssl.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import Icmp6NdOptionDnssl
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": (
                "Single short domain 'foo.bar' (9 bytes encoded, " "padded to 16 bytes total + 8 header = 24)."
            ),
            "_kwargs": {
                "lifetime": 3600,
                "domains": ("foo.bar",),
            },
            "_results": {
                "__len__": 24,
                "__bytes__": (
                    # Type=31, Length=3 (24 bytes), Reserved=0, Lifetime=3600.
                    b"\x1f\x03\x00\x00\x00\x00\x0e\x10"
                    # Domain encoding: 03 'foo' 03 'bar' 00 = 9 bytes.
                    # Padded with zeros to 16 bytes (8-octet alignment).
                    b"\x03foo\x03bar\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                "__str__": "dnssl (lifetime 3600, domains [foo.bar])",
            },
        },
        {
            "_description": (
                "Two domains 'example.com' + 'foo.bar' " "(13 + 9 = 22 bytes, padded to 24, +8 header = 32)."
            ),
            "_kwargs": {
                "lifetime": 600,
                "domains": ("example.com", "foo.bar"),
            },
            "_results": {
                "__len__": 32,
                "__bytes__": (
                    b"\x1f\x04\x00\x00\x00\x00\x02\x58" b"\x07example\x03com\x00" b"\x03foo\x03bar\x00" b"\x00\x00"
                ),
                "__str__": "dnssl (lifetime 600, domains [example.com, foo.bar])",
            },
        },
        {
            "_description": "Lifetime=0 (drop signal, RFC 8106 §5.2).",
            "_kwargs": {
                "lifetime": 0,
                "domains": ("local.lan",),
            },
            "_results": {
                "__len__": 24,
                "__bytes__": (b"\x1f\x03\x00\x00\x00\x00\x00\x00" b"\x05local\x03lan\x00\x00\x00\x00\x00\x00"),
                "__str__": "dnssl (lifetime 0, domains [local.lan])",
            },
        },
    ]
)
class TestIcmp6NdOptionDnsslAssembler(TestCase):
    """
    The ICMPv6 ND DNS Search List option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the option from _kwargs.
        """

        self._option = Icmp6NdOptionDnssl(**self._kwargs)

    def test__icmp6__nd__option__dnssl__len(self) -> None:
        """
        Ensure '__len__' returns the on-wire byte length
        (header + padded domain encoding rounded up to 8-byte
        alignment).

        Reference: RFC 8106 §5.2 (DNSSL byte length).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__dnssl__bytes(self) -> None:
        """
        Ensure '__bytes__' produces the expected wire encoding —
        RFC 1035 label sequences padded to 8-octet alignment.

        Reference: RFC 8106 §5.2 (DNSSL wire format).
        Reference: RFC 1035 §3.1 (domain-name label encoding).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__dnssl__str(self) -> None:
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
            "_description": "Single domain 'foo.bar' (padded to 16 bytes after header).",
            "_frame": (b"\x1f\x03\x00\x00\x00\x00\x0e\x10" b"\x03foo\x03bar\x00\x00\x00\x00\x00\x00\x00\x00"),
            "_results": {
                "lifetime": 3600,
                "domains": ("foo.bar",),
            },
        },
        {
            "_description": "Two domains 'example.com' + 'foo.bar'.",
            "_frame": (b"\x1f\x04\x00\x00\x00\x00\x02\x58" b"\x07example\x03com\x00" b"\x03foo\x03bar\x00" b"\x00\x00"),
            "_results": {
                "lifetime": 600,
                "domains": ("example.com", "foo.bar"),
            },
        },
        {
            "_description": "Header-only (length=1, no domains).",
            "_frame": b"\x1f\x01\x00\x00\x00\x00\x0e\x10",
            "_results": {
                "lifetime": 3600,
                "domains": (),
            },
        },
    ]
)
class TestIcmp6NdOptionDnsslParser(TestCase):
    """
    The ICMPv6 ND DNS Search List option parser tests.
    """

    _description: str
    _frame: bytes
    _results: dict[str, Any]

    def test__icmp6__nd__option__dnssl__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' decodes the wire bytes into the
        expected lifetime / domains tuple.

        Reference: RFC 8106 §5.2 (DNSSL wire format).
        """

        option = Icmp6NdOptionDnssl.from_buffer(self._frame)

        self.assertEqual(
            option.lifetime,
            self._results["lifetime"],
            msg=f"Unexpected lifetime for case: {self._description}",
        )
        self.assertEqual(
            option.domains,
            self._results["domains"],
            msg=f"Unexpected domains for case: {self._description}",
        )


class TestIcmp6NdOptionDnsslAsserts(TestCase):
    """
    Constructor argument validation for the DNSSL option.
    """

    def test__icmp6__nd__option__dnssl__rejects_oversized_label(self) -> None:
        """
        Ensure the constructor rejects a DNS label longer than
        63 octets.

        Reference: RFC 1035 §2.3.4 (label length limit).
        """

        too_long = "a" * 64
        with self.assertRaises(AssertionError):
            Icmp6NdOptionDnssl(lifetime=0, domains=(too_long + ".com",))

    def test__icmp6__nd__option__dnssl__rejects_non_ascii_label(self) -> None:
        """
        Ensure the constructor rejects a non-ASCII label —
        DNSSL is restricted to ASCII / IDNA encoded names.

        Reference: RFC 8106 §3.1 (DNSSL ASCII / IDNA constraint).
        """

        with self.assertRaises(AssertionError):
            Icmp6NdOptionDnssl(lifetime=0, domains=("schön.example",))
