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
Module contains tests for the ICMPv6 ND options container.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__options.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Network, MacAddress
from net_proto import (
    Icmp6IntegrityError,
    Icmp6NdOptionPi,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdOptionTlla,
    Icmp6NdOptionType,
    Icmp6NdOptionUnknown,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Icmp6NdOptions with four identical Slla entries.",
            "_args": [
                Icmp6NdOptionSlla(MacAddress()),
                Icmp6NdOptionSlla(MacAddress()),
                Icmp6NdOptionSlla(MacAddress()),
                Icmp6NdOptionSlla(MacAddress()),
            ],
            "_results": {
                "__len__": 32,
                "__str__": (
                    "slla 00:00:00:00:00:00, slla 00:00:00:00:00:00, " "slla 00:00:00:00:00:00, slla 00:00:00:00:00:00"
                ),
                "__repr__": (
                    "Icmp6NdOptions(options=[Icmp6NdOptionSlla(slla=MacAddress("
                    "'00:00:00:00:00:00')), Icmp6NdOptionSlla(slla=MacAddress("
                    "'00:00:00:00:00:00')), Icmp6NdOptionSlla(slla="
                    "MacAddress('00:00:00:00:00:00')), Icmp6NdOptionSlla(slla="
                    "MacAddress('00:00:00:00:00:00'))])"
                ),
                "__bytes__": (
                    b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
                    b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
                ),
                "__bool__": True,
                "slla": MacAddress(),
                "tlla": None,
                "pi": [],
            },
        },
        {
            "_description": "Icmp6NdOptions with a heterogeneous Slla+Tlla+Pi+Unknown set.",
            "_args": [
                Icmp6NdOptionSlla(MacAddress("01:02:03:04:05:06")),
                Icmp6NdOptionTlla(MacAddress("aa:bb:cc:dd:ee:ff")),
                Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=False,
                    flag_r=True,
                    valid_lifetime=100,
                    preferred_lifetime=50,
                    prefix=Ip6Network("2001:db8::/64"),
                ),
                Icmp6NdOptionUnknown(
                    type=Icmp6NdOptionType.from_int(99),
                    data=b"\x00\x01\x02\x03\x04\x05",
                ),
            ],
            "_results": {
                "__len__": 56,
                "__str__": (
                    "slla 01:02:03:04:05:06, tlla aa:bb:cc:dd:ee:ff, "
                    "prefix_info (prefix 2001:db8::/64, flags L-R, "
                    "valid_lifetime 100, preferred_lifetime 50), unk-99-8"
                ),
                "__repr__": (
                    "Icmp6NdOptions(options=[Icmp6NdOptionSlla(slla="
                    "MacAddress('01:02:03:04:05:06')), Icmp6NdOptionTlla("
                    "tlla=MacAddress('aa:bb:cc:dd:ee:ff')), Icmp6NdOptionPi("
                    "flag_l=True, flag_a=False, flag_r=True, valid_lifetime=100, "
                    "preferred_lifetime=50, prefix=Ip6Network('2001:db8::/64')), "
                    "Icmp6NdOptionUnknown(type=<Icmp6NdOptionType.UNKNOWN_99: 99>, "
                    "len=8, data=b'\\x00\\x01\\x02\\x03\\x04\\x05')])"
                ),
                "__bytes__": (
                    b"\x01\x01\x01\x02\x03\x04\x05\x06"
                    b"\x02\x01\xaa\xbb\xcc\xdd\xee\xff"
                    b"\x03\x04\x40\xa0\x00\x00\x00\x64\x00\x00\x00\x32\x00\x00\x00\x00"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x63\x01\x00\x01\x02\x03\x04\x05"
                ),
                "__bool__": True,
                "slla": MacAddress("01:02:03:04:05:06"),
                "tlla": MacAddress("aa:bb:cc:dd:ee:ff"),
            },
        },
        {
            "_description": "Icmp6NdOptions with no entries.",
            "_args": [],
            "_results": {
                "__len__": 0,
                "__str__": "",
                "__repr__": "Icmp6NdOptions(options=[])",
                "__bytes__": b"",
                "__bool__": False,
                "slla": None,
                "tlla": None,
                "pi": [],
            },
        },
    ]
)
class TestIcmp6NdOptionsAssembler(TestCase):
    """
    The ICMPv6 ND options container assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an Icmp6NdOptions container from the parametrized args.
        """

        self._options = Icmp6NdOptions(*self._args)

    def test__icmp6__nd__options__len(self) -> None:
        """
        Ensure '__len__()' returns the total wire-bytes length of the
        contained options.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            len(self._options),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__options__str(self) -> None:
        """
        Ensure '__str__()' returns a comma-separated join of per-option log
        strings.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            str(self._options),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__options__repr(self) -> None:
        """
        Ensure '__repr__()' returns the canonical Icmp6NdOptions(options=...)
        representation.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            repr(self._options),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__options__bytes(self) -> None:
        """
        Ensure '__bytes__()' emits the concatenation of each option's wire
        bytes.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            bytes(self._options),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__options__bool(self) -> None:
        """
        Ensure '__bool__()' reflects whether the container holds any options.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            bool(self._options),
            self._results["__bool__"],
            msg=f"Unexpected __bool__ for case: {self._description}",
        )


class TestIcmp6NdOptionsAccessors(TestCase):
    """
    The ICMPv6 ND options convenience-accessor tests.
    """

    def test__icmp6__nd__options__slla__none_when_absent(self) -> None:
        """
        Ensure the 'slla' property returns None when the container has no
        Slla option.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        options = Icmp6NdOptions(Icmp6NdOptionTlla(MacAddress("01:02:03:04:05:06")))

        self.assertIsNone(
            options.slla,
            msg="'slla' must be None when no Slla option is present.",
        )

    def test__icmp6__nd__options__slla__returns_first(self) -> None:
        """
        Ensure the 'slla' property returns the MacAddress of the first Slla
        option in insertion order.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        first = MacAddress("01:02:03:04:05:06")
        second = MacAddress("0a:0b:0c:0d:0e:0f")

        options = Icmp6NdOptions(
            Icmp6NdOptionSlla(first),
            Icmp6NdOptionSlla(second),
        )

        self.assertEqual(
            options.slla,
            first,
            msg="'slla' must return the first Slla option's MacAddress.",
        )

    def test__icmp6__nd__options__tlla__none_when_absent(self) -> None:
        """
        Ensure the 'tlla' property returns None when the container has no
        Tlla option.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        options = Icmp6NdOptions(Icmp6NdOptionSlla(MacAddress("01:02:03:04:05:06")))

        self.assertIsNone(
            options.tlla,
            msg="'tlla' must be None when no Tlla option is present.",
        )

    def test__icmp6__nd__options__tlla__returns_first(self) -> None:
        """
        Ensure the 'tlla' property returns the MacAddress of the first Tlla
        option in insertion order.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        first = MacAddress("aa:bb:cc:dd:ee:ff")
        second = MacAddress("00:11:22:33:44:55")

        options = Icmp6NdOptions(
            Icmp6NdOptionTlla(first),
            Icmp6NdOptionTlla(second),
        )

        self.assertEqual(
            options.tlla,
            first,
            msg="'tlla' must return the first Tlla option's MacAddress.",
        )

    def test__icmp6__nd__options__pi__empty_when_absent(self) -> None:
        """
        Ensure the 'pi' property returns an empty list when the container
        has no Pi option.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        options = Icmp6NdOptions(Icmp6NdOptionSlla(MacAddress("01:02:03:04:05:06")))

        self.assertEqual(
            options.pi,
            [],
            msg="'pi' must be an empty list when no Pi option is present.",
        )

    def test__icmp6__nd__options__pi__returns_all(self) -> None:
        """
        Ensure the 'pi' property returns one NdPrefixInfo per Pi option in
        insertion order.

        Reference: RFC 4861 §4.6.2 (Prefix Information option).
        """

        option_a = Icmp6NdOptionPi(
            flag_l=True,
            flag_a=False,
            flag_r=True,
            valid_lifetime=100,
            preferred_lifetime=50,
            prefix=Ip6Network("2001:db8::/64"),
        )
        option_b = Icmp6NdOptionPi(
            flag_l=False,
            flag_a=True,
            flag_r=False,
            valid_lifetime=200,
            preferred_lifetime=150,
            prefix=Ip6Network("2001:db8:1::/64"),
        )

        options = Icmp6NdOptions(option_a, Icmp6NdOptionSlla(MacAddress()), option_b)

        prefix_info = options.pi

        self.assertEqual(
            len(prefix_info),
            2,
            msg="'pi' must contain one NdPrefixInfo per Pi option.",
        )
        self.assertEqual(
            prefix_info[0].prefix,
            Ip6Network("2001:db8::/64"),
            msg="First NdPrefixInfo must mirror the first Pi option.",
        )
        self.assertEqual(
            prefix_info[1].prefix,
            Ip6Network("2001:db8:1::/64"),
            msg="Second NdPrefixInfo must mirror the second Pi option.",
        )


class TestIcmp6NdOptionsSequenceProtocol(TestCase):
    """
    The ICMPv6 ND options sequence-protocol tests (iter/getitem/index/
    contains/eq).
    """

    @override
    def setUp(self) -> None:
        """
        Build a three-option container used by every sequence-protocol test.
        """

        self._slla = Icmp6NdOptionSlla(MacAddress("01:02:03:04:05:06"))
        self._tlla = Icmp6NdOptionTlla(MacAddress("aa:bb:cc:dd:ee:ff"))
        self._unknown = Icmp6NdOptionUnknown(
            type=Icmp6NdOptionType.from_int(99),
            data=b"\x00\x01\x02\x03\x04\x05",
        )
        self._options = Icmp6NdOptions(self._slla, self._tlla, self._unknown)

    def test__icmp6__nd__options__iter(self) -> None:
        """
        Ensure iterating the container yields each option in insertion order.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            list(self._options),
            [self._slla, self._tlla, self._unknown],
            msg="Iteration must yield options in insertion order.",
        )

    def test__icmp6__nd__options__getitem(self) -> None:
        """
        Ensure indexing returns the option at the requested position.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(self._options[0], self._slla, msg="Index 0 must return the first option.")
        self.assertEqual(self._options[1], self._tlla, msg="Index 1 must return the second option.")
        self.assertEqual(self._options[2], self._unknown, msg="Index 2 must return the third option.")

    def test__icmp6__nd__options__contains(self) -> None:
        """
        Ensure '__contains__' recognises options held by the container and
        rejects ones not held.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertIn(
            self._slla,
            self._options,
            msg="Container must report membership for an option it holds.",
        )

        self.assertNotIn(
            Icmp6NdOptionSlla(MacAddress()),
            self._options,
            msg="Container must reject an option that does not compare equal.",
        )

    def test__icmp6__nd__options__index(self) -> None:
        """
        Ensure 'index()' returns the position of the requested option.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            self._options.index(self._tlla),
            1,
            msg="'index()' must return the position of the matching option.",
        )

    def test__icmp6__nd__options__eq__same_contents(self) -> None:
        """
        Ensure two Icmp6NdOptions with equal option lists compare equal.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        other = Icmp6NdOptions(self._slla, self._tlla, self._unknown)

        self.assertEqual(
            self._options,
            other,
            msg="Containers with equal option lists must compare equal.",
        )

    def test__icmp6__nd__options__eq__different_type(self) -> None:
        """
        Ensure Icmp6NdOptions does not compare equal to a non-Icmp6NdOptions
        object.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertNotEqual(
            self._options,
            object(),
            msg="Container must not compare equal to an unrelated object.",
        )


class TestIcmp6NdOptionsParser(TestCase):
    """
    The ICMPv6 ND options parser positive tests.
    """

    def test__icmp6__nd__options__from_buffer__homogeneous_slla(self) -> None:
        """
        Ensure from_buffer parses a buffer carrying four Slla options back
        into the reference container.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        buffer = (
            b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
            b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
        )

        self.assertEqual(
            Icmp6NdOptions.from_buffer(buffer),
            Icmp6NdOptions(
                Icmp6NdOptionSlla(MacAddress()),
                Icmp6NdOptionSlla(MacAddress()),
                Icmp6NdOptionSlla(MacAddress()),
                Icmp6NdOptionSlla(MacAddress()),
            ),
            msg="Parsed container must equal the reference Slla sequence.",
        )

    def test__icmp6__nd__options__from_buffer__mixed_known_and_unknown(
        self,
    ) -> None:
        """
        Ensure from_buffer dispatches each option-type byte to the correct
        parser, including the default case that produces
        Icmp6NdOptionUnknown.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        buffer = (
            b"\x01\x01\x01\x02\x03\x04\x05\x06"
            b"\x02\x01\xaa\xbb\xcc\xdd\xee\xff"
            b"\x03\x04\x40\xa0\x00\x00\x00\x64\x00\x00\x00\x32\x00\x00\x00\x00"
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x63\x01\x00\x01\x02\x03\x04\x05"
        )

        self.assertEqual(
            Icmp6NdOptions.from_buffer(buffer),
            Icmp6NdOptions(
                Icmp6NdOptionSlla(MacAddress("01:02:03:04:05:06")),
                Icmp6NdOptionTlla(MacAddress("aa:bb:cc:dd:ee:ff")),
                Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=False,
                    flag_r=True,
                    valid_lifetime=100,
                    preferred_lifetime=50,
                    prefix=Ip6Network("2001:db8::/64"),
                ),
                Icmp6NdOptionUnknown(
                    type=Icmp6NdOptionType.from_int(99),
                    data=b"\x00\x01\x02\x03\x04\x05",
                ),
            ),
            msg="Parsed container must equal the heterogeneous Slla+Tlla+Pi+Unknown reference.",
        )

    def test__icmp6__nd__options__from_buffer__empty(self) -> None:
        """
        Ensure from_buffer parses an empty buffer into an empty container.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            Icmp6NdOptions.from_buffer(b""),
            Icmp6NdOptions(),
            msg="Parsed container must be empty for an empty buffer.",
        )


class TestIcmp6NdOptionsValidateIntegrity(TestCase):
    """
    The ICMPv6 ND options validate_integrity() tests.
    """

    def test__icmp6__nd__options__validate_integrity__passes_on_valid_frame(
        self,
    ) -> None:
        """
        Ensure validate_integrity returns without error for a well-formed
        option sequence.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        frame = b"\x01\x01\x01\x02\x03\x04\x05\x06\x02\x01\xaa\xbb\xcc\xdd\xee\xff"

        Icmp6NdOptions.validate_integrity(frame=frame, offset=0)

    def test__icmp6__nd__options__validate_integrity__passes_on_empty_tail(
        self,
    ) -> None:
        """
        Ensure validate_integrity returns without error when offset already
        sits at the end of the frame.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        Icmp6NdOptions.validate_integrity(frame=b"\x00\x00\x00\x00", offset=4)

    def test__icmp6__nd__options__validate_integrity__zero_length_rejected(
        self,
    ) -> None:
        """
        Ensure validate_integrity raises Icmp6IntegrityError when an option
        encodes a length of zero 8-byte units.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        frame = b"\x01\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6NdOptions.validate_integrity(frame=frame, offset=0)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND option length must be greater than or equal to 8. Got: 0.",
            msg="Zero-length option must produce the minimum-length integrity error.",
        )

    def test__icmp6__nd__options__validate_integrity__overrun_rejected(
        self,
    ) -> None:
        """
        Ensure validate_integrity raises Icmp6IntegrityError when an option
        claims to extend past the end of the frame.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        frame = b"\x01\x02\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6NdOptions.validate_integrity(frame=frame, offset=0)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND option length must not "
            "extend past the header length. Got: offset=16, plen=8",
            msg="Overrun option must produce the past-end integrity error.",
        )
