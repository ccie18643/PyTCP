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
Module contains tests for the ICMPv6 ND Route Information option (RFC 4191 §2.3).

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__route_info.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address, Ip6Mask, Ip6Network
from net_proto import (
    Icmp6IntegrityError,
    Icmp6NdOptionRouteInfo,
    Icmp6NdOptionType,
    Icmp6NdRoutePreference,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIcmp6NdOptionRouteInfoAsserts(TestCase):
    """
    The ICMPv6 ND Route Information option constructor argument
    assert tests.
    """

    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        """
        Build a baseline-valid kwargs dict, with caller-supplied
        overrides.
        """

        base: dict[str, Any] = {
            "prf": Icmp6NdRoutePreference.MEDIUM,
            "route_lifetime": 1800,
            "prefix": Ip6Network((Ip6Address("2001:db8::"), Ip6Mask("/64"))),
        }
        base.update(overrides)
        return base

    def test__icmp6__nd__option__route_info__defaults_accepted(self) -> None:
        """
        Ensure the constructor accepts a baseline-valid kwargs
        bundle.

        Reference: RFC 4191 §2.3 (Route Information option).
        """

        option = Icmp6NdOptionRouteInfo(**self._kwargs())

        self.assertEqual(
            option.type,
            Icmp6NdOptionType.ROUTE_INFO,
            msg="The 'type' field must be ROUTE_INFO (24).",
        )

    def test__icmp6__nd__option__route_info__prf__not_enum(self) -> None:
        """
        Ensure the constructor rejects a 'prf' that is not an
        'Icmp6NdRoutePreference' enum member.

        Reference: RFC 4191 §2.3 (Prf field is a 2-bit enum).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionRouteInfo(**self._kwargs(prf=0))

        self.assertIn(
            "prf",
            str(error.exception),
            msg="Rejection must call out the offending field name.",
        )

    def test__icmp6__nd__option__route_info__route_lifetime__under_min(self) -> None:
        """
        Ensure the constructor rejects a negative 'route_lifetime'.

        Reference: RFC 4191 §2.3 (Route Lifetime is a 32-bit unsigned integer).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionRouteInfo(**self._kwargs(route_lifetime=-1))

        self.assertIn(
            "32-bit unsigned integer",
            str(error.exception),
            msg="Rejection must call out the uint32 constraint.",
        )

    def test__icmp6__nd__option__route_info__route_lifetime__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'route_lifetime' above
        the unsigned 32-bit ceiling.

        Reference: RFC 4191 §2.3 (Route Lifetime is a 32-bit unsigned integer).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionRouteInfo(**self._kwargs(route_lifetime=0x1_0000_0000))

        self.assertIn(
            "32-bit unsigned integer",
            str(error.exception),
            msg="Rejection must call out the uint32 constraint.",
        )

    def test__icmp6__nd__option__route_info__prefix__not_ip6_network(self) -> None:
        """
        Ensure the constructor rejects a 'prefix' that is not
        an 'Ip6Network' instance.

        Reference: RFC 4191 §2.3 (Prefix is identified by the variable-length field plus Prefix Length).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionRouteInfo(**self._kwargs(prefix="2001:db8::/64"))

        self.assertIn(
            "Ip6Network",
            str(error.exception),
            msg="Rejection must call out the Ip6Network constraint.",
        )


@parameterized_class(
    [
        {
            "_description": ("Default-route Route Info (Prefix Length = 0; " "Length = 1 = 8 bytes wire size)."),
            "_kwargs": {
                "prf": Icmp6NdRoutePreference.MEDIUM,
                "route_lifetime": 1800,
                "prefix": Ip6Network((Ip6Address("::"), Ip6Mask("/0"))),
            },
            "_results": {
                "__len__": 8,
                "__bytes__": (
                    # Type(1)=24 Length(1)=1 PrefixLen(1)=0 Prf-byte(1)=0x00
                    # Route Lifetime(4) = 1800 (0x00000708)
                    b"\x18\x01\x00\x00\x00\x00\x07\x08"
                ),
                "type": Icmp6NdOptionType.ROUTE_INFO,
                "len": 8,
                "prefix_length": 0,
                "prf": Icmp6NdRoutePreference.MEDIUM,
                "route_lifetime": 1800,
            },
        },
        {
            "_description": ("Route Info for /64 prefix (Length = 2 = 16 bytes wire size); " "high preference."),
            "_kwargs": {
                "prf": Icmp6NdRoutePreference.HIGH,
                "route_lifetime": 0xFFFFFFFF,  # infinity
                "prefix": Ip6Network((Ip6Address("2001:db8::"), Ip6Mask("/64"))),
            },
            "_results": {
                "__len__": 16,
                "__bytes__": (
                    # Type=24 Length=2 PrefixLen=64 Prf-byte=0x08 (Prf=01 << 3)
                    b"\x18\x02\x40\x08"
                    # Route Lifetime infinity
                    b"\xff\xff\xff\xff"
                    # First 8 bytes of prefix (zero-padded high bits)
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00"
                ),
                "type": Icmp6NdOptionType.ROUTE_INFO,
                "len": 16,
                "prefix_length": 64,
                "prf": Icmp6NdRoutePreference.HIGH,
                "route_lifetime": 0xFFFFFFFF,
            },
        },
        {
            "_description": ("Route Info for /128 host route (Length = 3 = 24 bytes); " "low preference."),
            "_kwargs": {
                "prf": Icmp6NdRoutePreference.LOW,
                "route_lifetime": 600,
                "prefix": Ip6Network((Ip6Address("2001:db8::1"), Ip6Mask("/128"))),
            },
            "_results": {
                "__len__": 24,
                "__bytes__": (
                    # Type=24 Length=3 PrefixLen=128 Prf-byte=0x18 (Prf=11 << 3)
                    b"\x18\x03\x80\x18"
                    # Route Lifetime 600 = 0x00000258
                    b"\x00\x00\x02\x58"
                    # 16 bytes of prefix
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "type": Icmp6NdOptionType.ROUTE_INFO,
                "len": 24,
                "prefix_length": 128,
                "prf": Icmp6NdRoutePreference.LOW,
                "route_lifetime": 600,
            },
        },
    ]
)
class TestIcmp6NdOptionRouteInfoAssembler(TestCase):
    """
    The ICMPv6 ND Route Information option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionRouteInfo(**self._kwargs)

    def test__icmp6__nd__option__route_info__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length —
        derived from prefix length (8 / 16 / 24).

        Reference: RFC 4191 §2.3 (Length depends on Prefix Length).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__route_info__bytes(self) -> None:
        """
        Ensure '__bytes__()' produces the expected wire bytes —
        type=24, length-in-8-octet-units, prefix-length, the
        Prf-encoded Reserved-Prf-Reserved byte, 32-bit Route
        Lifetime, then prefix truncated to 0 / 8 / 16 bytes.

        Reference: RFC 4191 §2.3 (Route Information wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__route_info__type(self) -> None:
        """
        Ensure the option 'type' field is ROUTE_INFO (24).

        Reference: RFC 4191 §2.3 (Type = 24).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__route_info__length(self) -> None:
        """
        Ensure the option 'len' field equals the expected
        derived length (in bytes).

        Reference: RFC 4191 §2.3 (Length in 8-octet units).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__route_info__prefix_length(self) -> None:
        """
        Ensure the 'prefix_length' property reflects the
        prefix's mask width.

        Reference: RFC 4191 §2.3 (Prefix Length = 0..128).
        """

        self.assertEqual(
            self._option.prefix_length,
            self._results["prefix_length"],
            msg=f"Unexpected 'prefix_length' for case: {self._description}",
        )

    def test__icmp6__nd__option__route_info__prf(self) -> None:
        """
        Ensure the 'prf' field carries the supplied
        preference enum value.

        Reference: RFC 4191 §2.1 (Prf field encoding).
        """

        self.assertEqual(
            self._option.prf,
            self._results["prf"],
            msg=f"Unexpected 'prf' for case: {self._description}",
        )

    def test__icmp6__nd__option__route_info__route_lifetime(self) -> None:
        """
        Ensure the 'route_lifetime' field carries the supplied
        seconds value (0xFFFFFFFF = infinity).

        Reference: RFC 4191 §2.3 (Route Lifetime).
        """

        self.assertEqual(
            self._option.route_lifetime,
            self._results["route_lifetime"],
            msg=f"Unexpected 'route_lifetime' for case: {self._description}",
        )


class TestIcmp6NdOptionRouteInfoParser(TestCase):
    """
    The ICMPv6 ND Route Information option parser positive tests.
    """

    def test__icmp6__nd__option__route_info__from_buffer__length_1(self) -> None:
        """
        Ensure 'from_buffer' parses a Length=1 (8 bytes,
        default-route) Route Info option.

        Reference: RFC 4191 §2.3 (Length = 1 when Prefix Length = 0).
        """

        wire = b"\x18\x01\x00\x00\x00\x00\x07\x08"
        option = Icmp6NdOptionRouteInfo.from_buffer(wire)

        self.assertEqual(
            option,
            Icmp6NdOptionRouteInfo(
                prf=Icmp6NdRoutePreference.MEDIUM,
                route_lifetime=1800,
                prefix=Ip6Network((Ip6Address("::"), Ip6Mask("/0"))),
            ),
            msg="Parsed Length=1 option must equal the reference.",
        )

    def test__icmp6__nd__option__route_info__from_buffer__round_trip_length_2(self) -> None:
        """
        Ensure assemble→parse round-trip preserves a /64
        Length=2 Route Info option.

        Reference: RFC 4191 §2.3 (Length = 2 when 0 < Prefix Length <= 64).
        """

        original = Icmp6NdOptionRouteInfo(
            prf=Icmp6NdRoutePreference.HIGH,
            route_lifetime=3600,
            prefix=Ip6Network((Ip6Address("2001:db8:0:1::"), Ip6Mask("/64"))),
        )
        parsed = Icmp6NdOptionRouteInfo.from_buffer(bytes(original))

        self.assertEqual(
            parsed,
            original,
            msg="Round-trip parse must reproduce the original /64 option.",
        )

    def test__icmp6__nd__option__route_info__from_buffer__round_trip_length_3(self) -> None:
        """
        Ensure assemble→parse round-trip preserves a /128
        Length=3 Route Info option.

        Reference: RFC 4191 §2.3 (Length = 3 when Prefix Length > 64).
        """

        original = Icmp6NdOptionRouteInfo(
            prf=Icmp6NdRoutePreference.LOW,
            route_lifetime=600,
            prefix=Ip6Network((Ip6Address("2001:db8::1"), Ip6Mask("/128"))),
        )
        parsed = Icmp6NdOptionRouteInfo.from_buffer(bytes(original))

        self.assertEqual(
            parsed,
            original,
            msg="Round-trip parse must reproduce the original /128 option.",
        )

    def test__icmp6__nd__option__route_info__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure 'from_buffer' parses a Route Info option when
        the buffer carries trailing bytes past the encoded
        option length — sibling options follow.

        Reference: RFC 4861 §4.6 (option chaining within a message).
        """

        wire = b"\x18\x01\x00\x00\x00\x00\x07\x08" + b"NEXT_OPT"
        option = Icmp6NdOptionRouteInfo.from_buffer(wire)

        self.assertEqual(
            option.len,
            8,
            msg="Trailing bytes past the encoded length must be ignored.",
        )


@parameterized_class(
    [
        {
            "_description": "Route Info option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\x18"],
            "_results": {
                "error": AssertionError,
                "error_message": ("The minimum length of the ICMPv6 ND Route Info option must be " "2 bytes. Got: 1"),
            },
        },
        {
            "_description": "Route Info option, buffer 'type' byte is not ROUTE_INFO.",
            "_args": [b"\xff\x01\x00\x00\x00\x00\x07\x08"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Route Info option type must be "
                    f"{Icmp6NdOptionType.ROUTE_INFO!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "Route Info option, encoded length 0 (impossible — minimum is 1).",
            "_args": [b"\x18\x00\x00\x00\x00\x00\x07\x08"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Route Info option length "
                    "value must be 8, 16, or 24 bytes. Got: 0"
                ),
            },
        },
        {
            "_description": "Route Info option, encoded length 4 (32 bytes — exceeds spec maximum).",
            "_args": [b"\x18\x04\x00\x00\x00\x00\x07\x08" + b"\x00" * 24],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Route Info option length "
                    "value must be 8, 16, or 24 bytes. Got: 32"
                ),
            },
        },
        {
            "_description": "Route Info option, prefix_length 65 with Length=2 (RFC violation).",
            "_args": [b"\x18\x02\x41\x00" + b"\x00" * 12],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Route Info option prefix "
                    "length must be at most 64 when option length is 16 bytes. Got: 65"
                ),
            },
        },
        {
            "_description": (
                "Route Info option, prefix_length 1 with Length=1 "
                "(RFC violation; Length=1 only valid for prefix_length=0)."
            ),
            "_args": [b"\x18\x01\x01\x00\x00\x00\x07\x08"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Route Info option prefix "
                    "length must be 0 when option length is 8 bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "Route Info option, prefix_length 129 (out of 0..128 range).",
            "_args": [b"\x18\x03\x81\x00" + b"\x00" * 20],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Route Info option prefix "
                    "length must be in 0..128. Got: 129"
                ),
            },
        },
        {
            "_description": "Route Info option, encoded length exceeds available buffer bytes.",
            "_args": [b"\x18\x02\x40\x00\x00\x00\x07\x08\x20\x01\x0d\xb8\x00\x00\x00"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Route Info option length "
                    "value must be less than or equal to the length of provided bytes "
                    "(15). Got: 16"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionRouteInfoParserFailures(TestCase):
    """
    The ICMPv6 ND Route Information option parser failure-path
    tests (asserts and integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__route_info__from_buffer__error(self) -> None:
        """
        Ensure 'from_buffer' raises the expected exception with
        the expected message for each malformed buffer.

        Reference: RFC 4191 §2.3 (Route Information wire format).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionRouteInfo.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
