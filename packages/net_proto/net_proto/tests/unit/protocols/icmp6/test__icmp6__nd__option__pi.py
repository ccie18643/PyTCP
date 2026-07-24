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
Module contains tests for the ICMPv6 ND Pi (Prefix Information) option.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__pi.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Network
from net_proto import (
    ICMP6__ND__OPTION__PI__LEN,
    UINT_32__MAX,
    UINT_32__MIN,
    Icmp6IntegrityError,
    Icmp6NdOptionPi,
    Icmp6NdOptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIcmp6NdOptionPiAsserts(TestCase):
    """
    The ICMPv6 ND Pi option constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default keyword arguments for the ICMPv6 ND Pi option
        constructor.
        """

        self._kwargs: dict[str, Any] = {
            "flag_l": False,
            "flag_a": False,
            "flag_r": False,
            "valid_lifetime": 0,
            "preferred_lifetime": 0,
            "prefix": Ip6Network(),
        }

    def test__icmp6__nd__option__pi__flag_l__not_boolean(self) -> None:
        """
        Ensure the constructor rejects a 'flag_l' argument that is not a
        boolean.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "flag_l": value})

        self.assertEqual(
            str(error.exception),
            f"The 'flag_l' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_l'.",
        )

    def test__icmp6__nd__option__pi__flag_a__not_boolean(self) -> None:
        """
        Ensure the constructor rejects a 'flag_a' argument that is not a
        boolean.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "flag_a": value})

        self.assertEqual(
            str(error.exception),
            f"The 'flag_a' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_a'.",
        )

    def test__icmp6__nd__option__pi__flag_r__not_boolean(self) -> None:
        """
        Ensure the constructor rejects a 'flag_r' argument that is not a
        boolean.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "flag_r": value})

        self.assertEqual(
            str(error.exception),
            f"The 'flag_r' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_r'.",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'valid_lifetime' argument below
        UINT_32__MIN.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "valid_lifetime": value})

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for under-min 'valid_lifetime'.",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'valid_lifetime' argument above
        UINT_32__MAX.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "valid_lifetime": value})

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for over-max 'valid_lifetime'.",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts UINT_32__MIN and UINT_32__MAX as
        'valid_lifetime' boundary values.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        for value in (UINT_32__MIN, UINT_32__MAX):
            with self.subTest(value=value):
                option = Icmp6NdOptionPi(**{**self._kwargs, "valid_lifetime": value})

                self.assertEqual(
                    option.valid_lifetime,
                    value,
                    msg=f"Constructed option.valid_lifetime must equal {value}.",
                )

    def test__icmp6__nd__option__pi__preferred_lifetime__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'preferred_lifetime' argument below
        UINT_32__MIN.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "preferred_lifetime": value})

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for under-min 'preferred_lifetime'.",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'preferred_lifetime' argument above
        UINT_32__MAX.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "preferred_lifetime": value})

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for over-max 'preferred_lifetime'.",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts UINT_32__MIN and UINT_32__MAX as
        'preferred_lifetime' boundary values.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        for value in (UINT_32__MIN, UINT_32__MAX):
            with self.subTest(value=value):
                option = Icmp6NdOptionPi(**{**self._kwargs, "preferred_lifetime": value})

                self.assertEqual(
                    option.preferred_lifetime,
                    value,
                    msg=f"Constructed option.preferred_lifetime must equal {value}.",
                )

    def test__icmp6__nd__option__pi__prefix__not_Ip6Network(self) -> None:
        """
        Ensure the constructor rejects a 'prefix' argument that is not an
        Ip6Network instance.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        value = "not an Ip6Network"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**{**self._kwargs, "prefix": value})

        self.assertEqual(
            str(error.exception),
            f"The 'prefix' field must be an Ip6Network. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip6Network 'prefix'.",
        )

    def test__icmp6__nd__option__pi__flags__default_accepted(self) -> None:
        """
        Ensure the constructor accepts the documented False defaults for the
        L/A/R flag fields.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        option = Icmp6NdOptionPi(
            valid_lifetime=0,
            preferred_lifetime=0,
            prefix=Ip6Network(),
        )

        self.assertFalse(option.flag_l, msg="Default 'flag_l' must be False.")
        self.assertFalse(option.flag_a, msg="Default 'flag_a' must be False.")
        self.assertFalse(option.flag_r, msg="Default 'flag_r' must be False.")


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Pi option with flags L-R, max valid_lifetime, /64 prefix.",
            "_kwargs": {
                "flag_l": True,
                "flag_a": False,
                "flag_r": True,
                "valid_lifetime": 4294967295,
                "preferred_lifetime": 0,
                "prefix": Ip6Network("2001:db8::/64"),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "prefix_info (prefix 2001:db8::/64, flags L-R, " "valid_lifetime 4294967295, preferred_lifetime 0)"
                ),
                "__repr__": (
                    "Icmp6NdOptionPi(flag_l=True, flag_a=False, flag_r=True, "
                    "valid_lifetime=4294967295, preferred_lifetime=0, "
                    "prefix=Ip6Network('2001:db8::/64'))"
                ),
                "__bytes__": (
                    b"\x03\x04\x40\xa0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                "type": Icmp6NdOptionType.PI,
                "len": 32,
                "flag_l": True,
                "flag_a": False,
                "flag_r": True,
                "valid_lifetime": 4294967295,
                "preferred_lifetime": 0,
                "prefix": Ip6Network("2001:db8::/64"),
            },
        },
        {
            "_description": "ICMPv6 ND Pi option with flag -A-, max preferred_lifetime, /128 prefix.",
            "_kwargs": {
                "flag_l": False,
                "flag_a": True,
                "flag_r": False,
                "valid_lifetime": 0,
                "preferred_lifetime": 4294967295,
                "prefix": Ip6Network("2007:db8::abcd/128"),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "prefix_info (prefix 2007:db8::abcd/128, flags -A-, "
                    "valid_lifetime 0, preferred_lifetime 4294967295)"
                ),
                "__repr__": (
                    "Icmp6NdOptionPi(flag_l=False, flag_a=True, flag_r=False, "
                    "valid_lifetime=0, preferred_lifetime=4294967295, "
                    "prefix=Ip6Network('2007:db8::abcd/128'))"
                ),
                "__bytes__": (
                    b"\x03\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd"
                ),
                "type": Icmp6NdOptionType.PI,
                "len": 32,
                "flag_l": False,
                "flag_a": True,
                "flag_r": False,
                "valid_lifetime": 0,
                "preferred_lifetime": 4294967295,
                "prefix": Ip6Network("2007:db8::abcd/128"),
            },
        },
        {
            "_description": "ICMPv6 ND Pi option with all flags clear, zero lifetimes, /0 prefix.",
            "_kwargs": {
                "flag_l": False,
                "flag_a": False,
                "flag_r": False,
                "valid_lifetime": 0,
                "preferred_lifetime": 0,
                "prefix": Ip6Network(),
            },
            "_results": {
                "__len__": 32,
                "__str__": ("prefix_info (prefix ::/0, flags ---, " "valid_lifetime 0, preferred_lifetime 0)"),
                "__repr__": (
                    "Icmp6NdOptionPi(flag_l=False, flag_a=False, flag_r=False, "
                    "valid_lifetime=0, preferred_lifetime=0, prefix=Ip6Network('::/0'))"
                ),
                "__bytes__": (
                    b"\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                "type": Icmp6NdOptionType.PI,
                "len": 32,
                "flag_l": False,
                "flag_a": False,
                "flag_r": False,
                "valid_lifetime": 0,
                "preferred_lifetime": 0,
                "prefix": Ip6Network(),
            },
        },
        {
            "_description": "ICMPv6 ND Pi option with all flags set, max lifetimes, /128 prefix.",
            "_kwargs": {
                "flag_l": True,
                "flag_a": True,
                "flag_r": True,
                "valid_lifetime": 4294967295,
                "preferred_lifetime": 4294967295,
                "prefix": Ip6Network("fe80::1/128"),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "prefix_info (prefix fe80::1/128, flags LAR, "
                    "valid_lifetime 4294967295, preferred_lifetime 4294967295)"
                ),
                "__repr__": (
                    "Icmp6NdOptionPi(flag_l=True, flag_a=True, flag_r=True, "
                    "valid_lifetime=4294967295, preferred_lifetime=4294967295, "
                    "prefix=Ip6Network('fe80::1/128'))"
                ),
                "__bytes__": (
                    b"\x03\x04\x80\xe0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "type": Icmp6NdOptionType.PI,
                "len": 32,
                "flag_l": True,
                "flag_a": True,
                "flag_r": True,
                "valid_lifetime": 4294967295,
                "preferred_lifetime": 4294967295,
                "prefix": Ip6Network("fe80::1/128"),
            },
        },
    ]
)
class TestIcmp6NdOptionPiAssembler(TestCase):
    """
    The ICMPv6 ND Pi option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the ICMPv6 ND Pi option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionPi(**self._kwargs)

    def test__icmp6__nd__option__pi__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__type(self) -> None:
        """
        Ensure the option 'type' field is Icmp6NdOptionType.PI.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__length(self) -> None:
        """
        Ensure the option 'len' field equals ICMP6__ND__OPTION__PI__LEN.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__flag_l(self) -> None:
        """
        Ensure the option 'flag_l' field carries the provided boolean.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.flag_l,
            self._results["flag_l"],
            msg=f"Unexpected 'flag_l' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__flag_a(self) -> None:
        """
        Ensure the option 'flag_a' field carries the provided boolean.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.flag_a,
            self._results["flag_a"],
            msg=f"Unexpected 'flag_a' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__flag_r(self) -> None:
        """
        Ensure the option 'flag_r' field carries the provided boolean.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.flag_r,
            self._results["flag_r"],
            msg=f"Unexpected 'flag_r' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__valid_lifetime(self) -> None:
        """
        Ensure the option 'valid_lifetime' field carries the provided value.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.valid_lifetime,
            self._results["valid_lifetime"],
            msg=f"Unexpected 'valid_lifetime' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime(self) -> None:
        """
        Ensure the option 'preferred_lifetime' field carries the provided
        value.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.preferred_lifetime,
            self._results["preferred_lifetime"],
            msg=f"Unexpected 'preferred_lifetime' for case: {self._description}",
        )

    def test__icmp6__nd__option__pi__prefix(self) -> None:
        """
        Ensure the option 'prefix' field carries the provided Ip6Network.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        self.assertEqual(
            self._option.prefix,
            self._results["prefix"],
            msg=f"Unexpected 'prefix' for case: {self._description}",
        )


class TestIcmp6NdOptionPiParser(TestCase):
    """
    The ICMPv6 ND Pi option parser positive tests.
    """

    def test__icmp6__nd__option__pi__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 32-byte Pi option whose buffer length
        exactly matches ICMP6__ND__OPTION__PI__LEN.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        buffer = (
            b"\x03\x04\x40\xa0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertEqual(
            len(buffer),
            ICMP6__ND__OPTION__PI__LEN,
            msg="Fixture must match ICMP6__ND__OPTION__PI__LEN.",
        )

        option = Icmp6NdOptionPi.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionPi(
                flag_l=True,
                flag_a=False,
                flag_r=True,
                valid_lifetime=4294967295,
                preferred_lifetime=0,
                prefix=Ip6Network("2001:db8::/64"),
            ),
            msg="Parsed option must equal the reference Icmp6NdOptionPi.",
        )

    def test__icmp6__nd__option__pi__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses a Pi option when the buffer carries
        trailing bytes past the 32-byte option payload.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        buffer = (
            b"\x03\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
            b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd" + b"ZH0PA"
        )

        option = Icmp6NdOptionPi.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionPi(
                flag_l=False,
                flag_a=True,
                flag_r=False,
                valid_lifetime=0,
                preferred_lifetime=4294967295,
                prefix=Ip6Network("2007:db8::abcd/128"),
            ),
            msg="Parsed option must equal the reference Icmp6NdOptionPi (trailing bytes ignored).",
        )

    def test__icmp6__nd__option__pi__from_buffer__all_flags_set(self) -> None:
        """
        Ensure from_buffer decodes all three flag bits (L/A/R) when set.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        buffer = (
            b"\x03\x04\x80\xe0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        )

        option = Icmp6NdOptionPi.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionPi(
                flag_l=True,
                flag_a=True,
                flag_r=True,
                valid_lifetime=4294967295,
                preferred_lifetime=4294967295,
                prefix=Ip6Network("fe80::1/128"),
            ),
            msg="Parsed option must equal the reference Icmp6NdOptionPi with all flags set.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Pi option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\x03"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the ICMPv6 ND Pi option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "ICMPv6 ND Pi option, buffer 'type' byte is not Icmp6NdOptionType.PI.",
            "_args": [
                b"\xff\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd",
            ],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Pi option type must be {Icmp6NdOptionType.PI!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Pi option, encoded length value (in 8-byte units) is not 4.",
            "_args": [
                b"\x03\x05\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd",
            ],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Pi option length value must be 32 bytes. Got: 40"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Pi option, encoded length value exceeds available buffer bytes.",
            "_args": [
                b"\x03\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab",
            ],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Pi option length value must be "
                    "less than or equal to the length of provided bytes (31). Got: 32"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionPiParserFailures(TestCase):
    """
    The ICMPv6 ND Pi option parser failure-path tests (asserts and
    integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__pi__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionPi.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
