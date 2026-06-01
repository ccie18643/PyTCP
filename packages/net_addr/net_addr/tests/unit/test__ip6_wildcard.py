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
This module contains tests for the NetAddr package IPv6 wildcard support class.

net_addr/tests/unit/test__ip6_wildcard.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import (
    Ip4Address,
    Ip4Wildcard,
    Ip6Address,
    Ip6Wildcard,
    Ip6WildcardFormatError,
    IpVersion,
)


@parameterized_class(
    [
        {
            "_description": "IPv6 wildcard :: (str) — match-all-exact",
            "_args": ["::"],
            "_results": {
                "__str__": "::",
                "__repr__": "Ip6Wildcard('::')",
                "__bytes__": (0).to_bytes(16),
                "__int__": 0,
                "__len__": 0,
            },
        },
        {
            "_description": "IPv6 wildcard ::ff (str) — low-byte don't-care",
            "_args": ["::ff"],
            "_results": {
                "__str__": "::ff",
                "__repr__": "Ip6Wildcard('::ff')",
                "__bytes__": (0xFF).to_bytes(16),
                "__int__": 0xFF,
                "__len__": 8,
            },
        },
        {
            "_description": "IPv6 wildcard ::ffff (int)",
            "_args": [0xFFFF],
            "_results": {
                "__str__": "::ffff",
                "__repr__": "Ip6Wildcard('::ffff')",
                "__bytes__": (0xFFFF).to_bytes(16),
                "__int__": 0xFFFF,
                "__len__": 16,
            },
        },
        {
            "_description": "IPv6 wildcard 1::ff (str) — non-contiguous",
            "_args": ["1::ff"],
            "_results": {
                "__str__": "1::ff",
                "__repr__": "Ip6Wildcard('1::ff')",
                "__bytes__": ((1 << 112) | 0xFF).to_bytes(16),
                "__int__": (1 << 112) | 0xFF,
                "__len__": 9,
            },
        },
        {
            "_description": "IPv6 wildcard ff00::fe (str) — non-contiguous Cisco-style",
            "_args": ["ff00::fe"],
            "_results": {
                "__str__": "ff00::fe",
                "__repr__": "Ip6Wildcard('ff00::fe')",
                "__bytes__": ((0xFF00 << 112) | 0xFE).to_bytes(16),
                "__int__": (0xFF00 << 112) | 0xFE,
                "__len__": 15,
            },
        },
        {
            "_description": "IPv6 wildcard all-ones (bytes) — match-any",
            "_args": [b"\xff" * 16],
            "_results": {
                "__str__": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Wildcard('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xff" * 16,
                "__int__": (1 << 128) - 1,
                "__len__": 128,
            },
        },
        {
            "_description": "IPv6 wildcard None — defaults to ::",
            "_args": [None],
            "_results": {
                "__str__": "::",
                "__repr__": "Ip6Wildcard('::')",
                "__bytes__": (0).to_bytes(16),
                "__int__": 0,
                "__len__": 0,
            },
        },
    ]
)
class TestNetAddrIp6Wildcard(TestCase):
    """
    The NetAddr IPv6 wildcard tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the IPv6 wildcard object from the testcase argument.
        """

        self._ip6_wildcard = Ip6Wildcard(*self._args)

    def test__net_addr__ip6_wildcard__str(self) -> None:
        """
        Ensure the IPv6 wildcard '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip6_wildcard),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__net_addr__ip6_wildcard__repr(self) -> None:
        """
        Ensure the IPv6 wildcard '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip6_wildcard),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__net_addr__ip6_wildcard__bytes(self) -> None:
        """
        Ensure the IPv6 wildcard '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._ip6_wildcard),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__net_addr__ip6_wildcard__int(self) -> None:
        """
        Ensure the IPv6 wildcard '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._ip6_wildcard),
            self._results["__int__"],
            msg=f"Unexpected __int__ for case: {self._description}",
        )

    def test__net_addr__ip6_wildcard__len(self) -> None:
        """
        Ensure the IPv6 wildcard '__len__()' returns the count of
        wildcarded (don't-care) bits.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._ip6_wildcard),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__net_addr__ip6_wildcard__version(self) -> None:
        """
        Ensure the IPv6 wildcard 'version' / 'is_ip4' / 'is_ip6'
        properties return correct values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_wildcard.version,
            IpVersion.IP6,
            msg=f"Unexpected version for case: {self._description}",
        )
        self.assertTrue(self._ip6_wildcard.is_ip6, msg="is_ip6 must be True for an Ip6Wildcard.")
        self.assertFalse(self._ip6_wildcard.is_ip4, msg="is_ip4 must be False for an Ip6Wildcard.")


@parameterized_class(
    [
        {
            "_description": "IPv6 wildcard: out-of-range int",
            "_args": [1 << 128],
            "_results": {
                "error_message": ("The IPv6 wildcard format is invalid: 340282366920938463463374607431768211456")
            },
        },
        {
            "_description": "IPv6 wildcard: negative int",
            "_args": [-1],
            "_results": {"error_message": "The IPv6 wildcard format is invalid: -1"},
        },
        {
            "_description": "IPv6 wildcard: wrong-length bytes",
            "_args": [b"\xff" * 15],
            "_results": {
                "error_message": (
                    "The IPv6 wildcard format is invalid: "
                    "b'\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff'"
                )
            },
        },
        {
            "_description": "IPv6 wildcard: invalid string",
            "_args": ["not-a-wildcard"],
            "_results": {"error_message": "The IPv6 wildcard format is invalid: 'not-a-wildcard'"},
        },
        {
            "_description": "IPv6 wildcard: unsupported type",
            "_args": [[]],
            "_results": {"error_message": "The IPv6 wildcard format is invalid: []"},
        },
    ]
)
class TestNetAddrIp6WildcardErrors(TestCase):
    """
    The NetAddr IPv6 wildcard error tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_wildcard__errors(self) -> None:
        """
        Ensure the IPv6 wildcard raises 'Ip6WildcardFormatError' on
        out-of-range / wrong-length / unparsable input (an arbitrary
        in-range bit pattern is always valid).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip6WildcardFormatError) as error:
            Ip6Wildcard(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )


class TestNetAddrIp6WildcardSemantics(TestCase):
    """
    The NetAddr IPv6 wildcard equality / hashing / copy tests.
    """

    def test__net_addr__ip6_wildcard__eq(self) -> None:
        """
        Ensure IPv6 wildcard equality is value- and type-based.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        wildcard = Ip6Wildcard("::ff")

        self.assertEqual(wildcard, wildcard, msg="A wildcard must equal itself.")
        self.assertEqual(wildcard, Ip6Wildcard(0xFF), msg="Wildcards with the same value must be equal.")
        self.assertNotEqual(wildcard, Ip6Wildcard("::ffff"), msg="Different wildcards must not be equal.")
        self.assertNotEqual(wildcard, "::ff", msg="A wildcard must not equal a foreign type.")
        self.assertNotEqual(
            wildcard,
            Ip4Wildcard("0.0.0.255"),
            msg="An Ip6Wildcard must not equal an Ip4Wildcard.",
        )

    def test__net_addr__ip6_wildcard__hash(self) -> None:
        """
        Ensure equal IPv6 wildcards hash equal and are usable as keys.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Wildcard("::ff")
        b = Ip6Wildcard(0xFF)

        self.assertEqual(hash(a), hash(b), msg="Equal wildcards must hash equal.")
        self.assertEqual(len({a, b}), 1, msg="Equal wildcards must collapse in a set.")
        self.assertEqual({a: "x"}[b], "x", msg="Equal wildcards must index the same dict entry.")

    def test__net_addr__ip6_wildcard__copy(self) -> None:
        """
        Ensure an IPv6 wildcard copy-constructs from another wildcard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip6Wildcard("ff00::fe")

        self.assertEqual(
            Ip6Wildcard(source),
            source,
            msg="Copy-constructed Ip6Wildcard must equal its source.",
        )


class TestNetAddrIp6WildcardOrAddress(TestCase):
    """
    The NetAddr IPv6 wildcard | address (canonical
    representative) operator tests.
    """

    def test__net_addr__ip6_wildcard__or_address(self) -> None:
        """
        Ensure 'address | wildcard' (and the reflected form)
        yields the canonical representative — every don't-care
        bit (wildcard=1) forced high, every care bit unchanged.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for addr, wild, expected in [
            ("2001:db8::a", "::f", "2001:db8::f"),
            ("2001:db8::", "::f", "2001:db8::f"),
            ("2001:db8::10", "::f", "2001:db8::1f"),
            ("2001:db8::1", "::ffff", "2001:db8::ffff"),
            ("::", "::", "::"),
        ]:
            with self.subTest(addr=addr, wild=wild):
                a = Ip6Address(addr)
                w = Ip6Wildcard(wild)
                self.assertEqual(
                    a | w,
                    Ip6Address(expected),
                    msg=f"{addr} | {wild} must be {expected}.",
                )
                self.assertEqual(
                    w | a,
                    Ip6Address(expected),
                    msg=f"{wild} | {addr} (reflected) must be {expected}.",
                )
                self.assertIsInstance(
                    a | w,
                    Ip6Address,
                    msg="address | wildcard must return an Ip6Address.",
                )

    def test__net_addr__ip6_wildcard__or_address_match_idiom(self) -> None:
        """
        Ensure the ACL match idiom '(candidate | w) == (base | w)'
        admits members and rejects non-members of the
        wildcard-equivalence class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        w = Ip6Wildcard("::ffff")
        base = Ip6Address("2001:db8::")
        self.assertEqual(
            Ip6Address("2001:db8::abcd") | w,
            base | w,
            msg="2001:db8::abcd must match 2001:db8::/::ffff.",
        )
        self.assertNotEqual(
            Ip6Address("2001:db8::1:abcd") | w,
            base | w,
            msg="2001:db8::1:abcd must not match 2001:db8::/::ffff.",
        )

    def test__net_addr__ip6_wildcard__or_rejects_foreign_operand(self) -> None:
        """
        Ensure a non-address or cross-version operand yields
        'TypeError' rather than a silent wrong result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        w = Ip6Wildcard("::ffff")
        with self.assertRaises(TypeError):
            _ = w | 5
        with self.assertRaises(TypeError):
            _ = Ip4Address("10.0.0.1") | w


class TestNetAddrIp6WildcardWhitespace(TestCase):
    """
    The NetAddr Ip6Wildcard surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip6_wildcard__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("::ffff",):
            expected = Ip6Wildcard(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip6Wildcard(wrapped),
                        expected,
                        msg=f"Ip6Wildcard({wrapped!r}) must equal Ip6Wildcard({value!r}).",
                    )
