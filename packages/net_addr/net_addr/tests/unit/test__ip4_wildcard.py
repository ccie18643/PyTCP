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
This module contains tests for the NetAddr package IPv4 wildcard support class.

net_addr/tests/unit/test__ip4_wildcard.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import (
    Ip4Address,
    Ip4Wildcard,
    Ip4WildcardFormatError,
    Ip6Address,
    Ip6Wildcard,
    IpVersion,
)


@parameterized_class(
    [
        {
            "_description": "IPv4 wildcard 0.0.0.0 (str) — match-all-exact",
            "_args": ["0.0.0.0"],
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Wildcard('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "__len__": 0,
            },
        },
        {
            "_description": "IPv4 wildcard 0.0.0.255 (str) — /24 hostmask special case",
            "_args": ["0.0.0.255"],
            "_results": {
                "__str__": "0.0.0.255",
                "__repr__": "Ip4Wildcard('0.0.0.255')",
                "__bytes__": b"\x00\x00\x00\xff",
                "__int__": 255,
                "__len__": 8,
            },
        },
        {
            "_description": "IPv4 wildcard 0.0.0.240 (str) — non-contiguous Cisco mask",
            "_args": ["0.0.0.240"],
            "_results": {
                "__str__": "0.0.0.240",
                "__repr__": "Ip4Wildcard('0.0.0.240')",
                "__bytes__": b"\x00\x00\x00\xf0",
                "__int__": 240,
                "__len__": 4,
            },
        },
        {
            "_description": "IPv4 wildcard 0.255.0.255 (int) — classic Cisco odd-subnet match",
            "_args": [0x00FF_00FF],
            "_results": {
                "__str__": "0.255.0.255",
                "__repr__": "Ip4Wildcard('0.255.0.255')",
                "__bytes__": b"\x00\xff\x00\xff",
                "__int__": 0x00FF_00FF,
                "__len__": 16,
            },
        },
        {
            "_description": "IPv4 wildcard 0.0.0.254 (bytes) — match even hosts",
            "_args": [b"\x00\x00\x00\xfe"],
            "_results": {
                "__str__": "0.0.0.254",
                "__repr__": "Ip4Wildcard('0.0.0.254')",
                "__bytes__": b"\x00\x00\x00\xfe",
                "__int__": 254,
                "__len__": 7,
            },
        },
        {
            "_description": "IPv4 wildcard 255.255.255.255 (bytes) — match-any / /0 hostmask",
            "_args": [b"\xff\xff\xff\xff"],
            "_results": {
                "__str__": "255.255.255.255",
                "__repr__": "Ip4Wildcard('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 0xFFFF_FFFF,
                "__len__": 32,
            },
        },
        {
            "_description": "IPv4 wildcard None — defaults to 0.0.0.0",
            "_args": [None],
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Wildcard('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "__len__": 0,
            },
        },
    ]
)
class TestNetAddrIp4Wildcard(TestCase):
    """
    The NetAddr IPv4 wildcard tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the IPv4 wildcard object from the testcase argument.
        """

        self._ip4_wildcard = Ip4Wildcard(*self._args)

    def test__net_addr__ip4_wildcard__str(self) -> None:
        """
        Ensure the IPv4 wildcard '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip4_wildcard),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__net_addr__ip4_wildcard__repr(self) -> None:
        """
        Ensure the IPv4 wildcard '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip4_wildcard),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__net_addr__ip4_wildcard__bytes(self) -> None:
        """
        Ensure the IPv4 wildcard '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._ip4_wildcard),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__net_addr__ip4_wildcard__int(self) -> None:
        """
        Ensure the IPv4 wildcard '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._ip4_wildcard),
            self._results["__int__"],
            msg=f"Unexpected __int__ for case: {self._description}",
        )

    def test__net_addr__ip4_wildcard__len(self) -> None:
        """
        Ensure the IPv4 wildcard '__len__()' returns the count of
        wildcarded (don't-care) bits.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._ip4_wildcard),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__net_addr__ip4_wildcard__version(self) -> None:
        """
        Ensure the IPv4 wildcard 'version' / 'is_ip4' / 'is_ip6'
        properties return correct values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_wildcard.version,
            IpVersion.IP4,
            msg=f"Unexpected version for case: {self._description}",
        )
        self.assertTrue(self._ip4_wildcard.is_ip4, msg="is_ip4 must be True for an Ip4Wildcard.")
        self.assertFalse(self._ip4_wildcard.is_ip6, msg="is_ip6 must be False for an Ip4Wildcard.")


@parameterized_class(
    [
        {
            "_description": "IPv4 wildcard: out-of-range int",
            "_args": [0x1_0000_0000],
            "_results": {"error_message": "The IPv4 wildcard format is invalid: 4294967296"},
        },
        {
            "_description": "IPv4 wildcard: negative int",
            "_args": [-1],
            "_results": {"error_message": "The IPv4 wildcard format is invalid: -1"},
        },
        {
            "_description": "IPv4 wildcard: wrong-length bytes",
            "_args": [b"\x00\x00\xff"],
            "_results": {"error_message": "The IPv4 wildcard format is invalid: b'\\x00\\x00\\xff'"},
        },
        {
            "_description": "IPv4 wildcard: invalid string",
            "_args": ["not-a-wildcard"],
            "_results": {"error_message": "The IPv4 wildcard format is invalid: 'not-a-wildcard'"},
        },
        {
            "_description": "IPv4 wildcard: unsupported type",
            "_args": [[]],
            "_results": {"error_message": "The IPv4 wildcard format is invalid: []"},
        },
        {
            "_description": "IPv4 wildcard: leading-zero octet",
            "_args": ["0.0.0.0255"],
            "_results": {"error_message": "The IPv4 wildcard format is invalid: '0.0.0.0255'"},
        },
    ]
)
class TestNetAddrIp4WildcardErrors(TestCase):
    """
    The NetAddr IPv4 wildcard error tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_wildcard__errors(self) -> None:
        """
        Ensure the IPv4 wildcard raises 'Ip4WildcardFormatError' on
        out-of-range / wrong-length / unparsable input (an arbitrary
        in-range bit pattern is always valid — wildcards are not
        contiguity-constrained).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip4WildcardFormatError) as error:
            Ip4Wildcard(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )


class TestNetAddrIp4WildcardSemantics(TestCase):
    """
    The NetAddr IPv4 wildcard equality / hashing / copy tests.
    """

    def test__net_addr__ip4_wildcard__eq(self) -> None:
        """
        Ensure IPv4 wildcard equality is value- and type-based.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        wildcard = Ip4Wildcard("0.0.0.255")

        self.assertEqual(wildcard, wildcard, msg="A wildcard must equal itself.")
        self.assertEqual(wildcard, Ip4Wildcard(255), msg="Wildcards with the same value must be equal.")
        self.assertNotEqual(wildcard, Ip4Wildcard("0.0.255.255"), msg="Different wildcards must not be equal.")
        self.assertNotEqual(wildcard, "0.0.0.255", msg="A wildcard must not equal a foreign type.")
        self.assertNotEqual(
            wildcard,
            Ip6Wildcard("::ff"),
            msg="An Ip4Wildcard must not equal an Ip6Wildcard.",
        )

    def test__net_addr__ip4_wildcard__hash(self) -> None:
        """
        Ensure equal IPv4 wildcards hash equal and are usable as keys.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Wildcard("0.0.0.255")
        b = Ip4Wildcard(255)

        self.assertEqual(hash(a), hash(b), msg="Equal wildcards must hash equal.")
        self.assertEqual(len({a, b}), 1, msg="Equal wildcards must collapse in a set.")
        self.assertEqual({a: "x"}[b], "x", msg="Equal wildcards must index the same dict entry.")

    def test__net_addr__ip4_wildcard__copy(self) -> None:
        """
        Ensure an IPv4 wildcard copy-constructs from another wildcard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip4Wildcard("0.255.0.255")

        self.assertEqual(
            Ip4Wildcard(source),
            source,
            msg="Copy-constructed Ip4Wildcard must equal its source.",
        )


class TestNetAddrIp4WildcardOrAddress(TestCase):
    """
    The NetAddr IPv4 wildcard | address (canonical
    representative) operator tests.
    """

    def test__net_addr__ip4_wildcard__or_address(self) -> None:
        """
        Ensure 'address | wildcard' (and the reflected form)
        yields the canonical representative — every don't-care
        bit (wildcard=1) forced high, every care bit unchanged
        — for contiguous and non-contiguous wildcards alike.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for addr, wild, expected in [
            ("10.1.1.42", "0.0.0.255", "10.1.1.255"),
            ("10.1.1.0", "0.0.0.255", "10.1.1.255"),
            ("10.1.2.42", "0.0.0.255", "10.1.2.255"),
            ("10.1.1.5", "0.0.0.254", "10.1.1.255"),
            ("10.1.1.4", "0.0.0.254", "10.1.1.254"),
            ("0.0.0.0", "0.0.0.0", "0.0.0.0"),
        ]:
            with self.subTest(addr=addr, wild=wild):
                a = Ip4Address(addr)
                w = Ip4Wildcard(wild)
                self.assertEqual(
                    a | w,
                    Ip4Address(expected),
                    msg=f"{addr} | {wild} must be {expected}.",
                )
                self.assertEqual(
                    w | a,
                    Ip4Address(expected),
                    msg=f"{wild} | {addr} (reflected) must be {expected}.",
                )
                self.assertIsInstance(
                    a | w,
                    Ip4Address,
                    msg="address | wildcard must return an Ip4Address.",
                )

    def test__net_addr__ip4_wildcard__or_address_match_idiom(self) -> None:
        """
        Ensure the ACL match idiom '(candidate | w) == (base | w)'
        admits members and rejects non-members of the
        wildcard-equivalence class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        w = Ip4Wildcard("0.0.0.255")
        base = Ip4Address("10.1.1.0")
        self.assertEqual(
            Ip4Address("10.1.1.200") | w,
            base | w,
            msg="10.1.1.200 must match 10.1.1.0/0.0.0.255.",
        )
        self.assertNotEqual(
            Ip4Address("10.1.2.200") | w,
            base | w,
            msg="10.1.2.200 must not match 10.1.1.0/0.0.0.255.",
        )

    def test__net_addr__ip4_wildcard__or_rejects_foreign_operand(self) -> None:
        """
        Ensure a non-address or cross-version operand yields
        'TypeError' rather than a silent wrong result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        w = Ip4Wildcard("0.0.0.255")
        with self.assertRaises(TypeError):
            _ = w | 5
        with self.assertRaises(TypeError):
            _ = Ip6Address("::1") | w


class TestNetAddrIp4WildcardWhitespace(TestCase):
    """
    The NetAddr Ip4Wildcard surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip4_wildcard__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("0.0.0.255",):
            expected = Ip4Wildcard(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip4Wildcard(wrapped),
                        expected,
                        msg=f"Ip4Wildcard({wrapped!r}) must equal Ip4Wildcard({value!r}).",
                    )
