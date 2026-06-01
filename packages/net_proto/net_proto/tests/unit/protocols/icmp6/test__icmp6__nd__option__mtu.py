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
Module contains tests for the ICMPv6 ND MTU option (RFC 4861 §4.6.4).

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__mtu.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    ICMP6__ND__OPTION__MTU__LEN,
    Icmp6IntegrityError,
    Icmp6NdOptionMtu,
    Icmp6NdOptionType,
)


class TestIcmp6NdOptionMtuAsserts(TestCase):
    """
    The ICMPv6 ND MTU option constructor argument assert tests.
    """

    def test__icmp6__nd__option__mtu__mtu__under_min(self) -> None:
        """
        Ensure the constructor rejects a negative 'mtu' value —
        the wire field is unsigned.

        Reference: RFC 4861 §4.6.4 (MTU is a 32-bit unsigned integer).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionMtu(mtu=-1)

        self.assertIn(
            "32-bit unsigned integer",
            str(error.exception),
            msg="Rejection must call out the uint32 constraint.",
        )

    def test__icmp6__nd__option__mtu__mtu__over_max(self) -> None:
        """
        Ensure the constructor rejects an 'mtu' value above the
        unsigned 32-bit ceiling.

        Reference: RFC 4861 §4.6.4 (MTU is a 32-bit unsigned integer).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionMtu(mtu=0x1_0000_0000)

        self.assertIn(
            "32-bit unsigned integer",
            str(error.exception),
            msg="Rejection must call out the uint32 constraint.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND MTU option carrying mtu=1500 (Ethernet default).",
            "_kwargs": {"mtu": 1500},
            "_results": {
                "__len__": 8,
                "__str__": "mtu 1500",
                "__repr__": "Icmp6NdOptionMtu(mtu=1500)",
                "__bytes__": b"\x05\x01\x00\x00\x00\x00\x05\xdc",
                "type": Icmp6NdOptionType.MTU,
                "len": 8,
                "mtu": 1500,
            },
        },
        {
            "_description": "ICMPv6 ND MTU option carrying mtu=1280 (RFC 8200 IPv6 minimum).",
            "_kwargs": {"mtu": 1280},
            "_results": {
                "__len__": 8,
                "__str__": "mtu 1280",
                "__repr__": "Icmp6NdOptionMtu(mtu=1280)",
                "__bytes__": b"\x05\x01\x00\x00\x00\x00\x05\x00",
                "type": Icmp6NdOptionType.MTU,
                "len": 8,
                "mtu": 1280,
            },
        },
        {
            "_description": "ICMPv6 ND MTU option carrying mtu=9000 (jumbo Ethernet).",
            "_kwargs": {"mtu": 9000},
            "_results": {
                "__len__": 8,
                "__str__": "mtu 9000",
                "__repr__": "Icmp6NdOptionMtu(mtu=9000)",
                "__bytes__": b"\x05\x01\x00\x00\x00\x00\x23\x28",
                "type": Icmp6NdOptionType.MTU,
                "len": 8,
                "mtu": 9000,
            },
        },
        {
            "_description": "ICMPv6 ND MTU option carrying mtu=0 (zero-MTU edge case).",
            "_kwargs": {"mtu": 0},
            "_results": {
                "__len__": 8,
                "__str__": "mtu 0",
                "__repr__": "Icmp6NdOptionMtu(mtu=0)",
                "__bytes__": b"\x05\x01\x00\x00\x00\x00\x00\x00",
                "type": Icmp6NdOptionType.MTU,
                "len": 8,
                "mtu": 0,
            },
        },
        {
            "_description": "ICMPv6 ND MTU option carrying mtu=4294967295 (uint32 max).",
            "_kwargs": {"mtu": 0xFFFFFFFF},
            "_results": {
                "__len__": 8,
                "__str__": "mtu 4294967295",
                "__repr__": "Icmp6NdOptionMtu(mtu=4294967295)",
                "__bytes__": b"\x05\x01\x00\x00\xff\xff\xff\xff",
                "type": Icmp6NdOptionType.MTU,
                "len": 8,
                "mtu": 0xFFFFFFFF,
            },
        },
    ]
)
class TestIcmp6NdOptionMtuAssembler(TestCase):
    """
    The ICMPv6 ND MTU option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionMtu(**self._kwargs)

    def test__icmp6__nd__option__mtu__len(self) -> None:
        """
        Ensure '__len__()' returns the expected 8 bytes.

        Reference: RFC 4861 §4.6.4 (MTU option is fixed 8 bytes).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__mtu__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__option__mtu__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__option__mtu__bytes(self) -> None:
        """
        Ensure '__bytes__()' produces the expected wire bytes —
        type=5, length=1 (in 8-octet units), 16-bit zero
        Reserved, then 32-bit MTU.

        Reference: RFC 4861 §4.6.4 (MTU wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__mtu__type(self) -> None:
        """
        Ensure the option 'type' field is MTU (5).

        Reference: RFC 4861 §4.6.4 (Type = 5).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__mtu__length(self) -> None:
        """
        Ensure the option 'len' field equals the fixed 8.

        Reference: RFC 4861 §4.6.4 (Length = 1 in 8-octet units = 8 bytes).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__mtu__mtu(self) -> None:
        """
        Ensure the 'mtu' field carries the supplied integer.

        Reference: RFC 4861 §4.6.4 (MTU = 32-bit unsigned integer).
        """

        self.assertEqual(
            self._option.mtu,
            self._results["mtu"],
            msg=f"Unexpected 'mtu' for case: {self._description}",
        )


class TestIcmp6NdOptionMtuParser(TestCase):
    """
    The ICMPv6 ND MTU option parser positive tests.
    """

    def test__icmp6__nd__option__mtu__from_buffer__exact_length(self) -> None:
        """
        Ensure 'from_buffer' parses a buffer whose length is
        exactly the 8-byte option size.

        Reference: RFC 4861 §4.6.4 (MTU wire format).
        """

        buffer = b"\x05\x01\x00\x00\x00\x00\x05\xdc"

        self.assertEqual(
            len(buffer),
            ICMP6__ND__OPTION__MTU__LEN,
            msg="Fixture must match ICMP6__ND__OPTION__MTU__LEN.",
        )

        option = Icmp6NdOptionMtu.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionMtu(mtu=1500),
            msg="Parsed option must equal the reference Icmp6NdOptionMtu.",
        )

    def test__icmp6__nd__option__mtu__from_buffer__round_trip(self) -> None:
        """
        Ensure assemble→parse round-trip preserves the MTU
        value exactly.

        Reference: RFC 4861 §4.6.4 (MTU wire format).
        """

        original = Icmp6NdOptionMtu(mtu=9000)

        parsed = Icmp6NdOptionMtu.from_buffer(bytes(original))

        self.assertEqual(
            parsed,
            original,
            msg="Round-trip parse must reproduce the original option.",
        )

    def test__icmp6__nd__option__mtu__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure 'from_buffer' parses an MTU option when the
        buffer carries trailing bytes past the encoded option
        length — sibling options follow.

        Reference: RFC 4861 §4.6 (option chaining within a message).
        """

        buffer = b"\x05\x01\x00\x00\x00\x00\x05\xdc" + b"NEXT_OPT"

        option = Icmp6NdOptionMtu.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionMtu(mtu=1500),
            msg="Trailing bytes past the encoded length must be ignored.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND MTU option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\x05"],
            "_results": {
                "error": AssertionError,
                "error_message": ("The minimum length of the ICMPv6 ND MTU option must be 2 bytes. Got: 1"),
            },
        },
        {
            "_description": "ICMPv6 ND MTU option, buffer 'type' byte is not MTU.",
            "_args": [b"\xff\x01\x00\x00\x00\x00\x05\xdc"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND MTU option type must be {Icmp6NdOptionType.MTU!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND MTU option, encoded length not equal to 8.",
            "_args": [b"\x05\x02\x00\x00\x00\x00\x05\xdc"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND MTU option length value " "must be 8 bytes. Got: 16"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND MTU option, encoded length exceeds available buffer bytes.",
            "_args": [b"\x05\x01\x00\x00\x00\x00\x05"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND MTU option length value "
                    "must be less than or equal to the length of provided bytes (7). Got: 8"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionMtuParserFailures(TestCase):
    """
    The ICMPv6 ND MTU option parser failure-path tests
    (asserts and integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__mtu__from_buffer__error(self) -> None:
        """
        Ensure 'from_buffer' raises the expected exception with
        the expected message for each malformed buffer.

        Reference: RFC 4861 §4.6.4 (MTU option wire format).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionMtu.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
