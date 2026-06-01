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
Module contains tests for the DHCPv4 IP Address Lease Time option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__lease_time.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    UINT_32__MAX,
    UINT_32__MIN,
    Dhcp4IntegrityError,
    Dhcp4OptionLeaseTime,
    Dhcp4OptionType,
)


class TestDhcp4OptionLeaseTimeAsserts(TestCase):
    """
    The DHCPv4 IP Address Lease Time option constructor argument assert tests.
    """

    def test__dhcp4__option__lease_time__over_max(self) -> None:
        """
        Ensure the constructor raises when 'lease_time' exceeds UINT_32__MAX.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionLeaseTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'lease_time' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'lease_time' over-max assert message.",
        )

    def test__dhcp4__option__lease_time__under_min(self) -> None:
        """
        Ensure the constructor raises when 'lease_time' is below zero.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionLeaseTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'lease_time' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'lease_time' under-min assert message.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 IP Address Lease Time option (zero).",
            "_args": [0],
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 0",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=0)",
                "__bytes__": (
                    # DHCPv4 IP Address Lease Time option [RFC 2132]
                    #   Code : 0x33 (51, IP Address Lease Time)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 00 00 00 00  (0 seconds)
                    b"\x33\x04\x00\x00\x00\x00"
                ),
                "lease_time": 0,
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one minute).",
            "_args": [60],
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 60",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=60)",
                "__bytes__": (
                    # DHCPv4 IP Address Lease Time option [RFC 2132]
                    #   Code : 0x33 (51, IP Address Lease Time)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 00 00 00 3c  (60 seconds)
                    b"\x33\x04\x00\x00\x00\x3c"
                ),
                "lease_time": 60,
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one day).",
            "_args": [86400],
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 86400",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=86400)",
                "__bytes__": (
                    # DHCPv4 IP Address Lease Time option [RFC 2132]
                    #   Code : 0x33 (51, IP Address Lease Time)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 00 01 51 80  (86400 seconds = 24 h)
                    b"\x33\x04\x00\x01\x51\x80"
                ),
                "lease_time": 86400,
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (max uint32, infinite lease).",
            "_args": [UINT_32__MAX],
            "_results": {
                "__len__": 6,
                "__str__": f"lease_time {UINT_32__MAX}",
                "__repr__": f"Dhcp4OptionLeaseTime(lease_time={UINT_32__MAX})",
                "__bytes__": (
                    # DHCPv4 IP Address Lease Time option [RFC 2132]
                    #   Code : 0x33 (51, IP Address Lease Time)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff ff ff ff  (RFC 2131 §3.3 "infinite" lease)
                    b"\x33\x04\xff\xff\xff\xff"
                ),
                "lease_time": UINT_32__MAX,
            },
        },
    ]
)
class TestDhcp4OptionLeaseTimeAssembler(TestCase):
    """
    The DHCPv4 IP Address Lease Time option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 IP Address Lease Time option object.
        """

        self._option = Dhcp4OptionLeaseTime(*self._args)

    def test__dhcp4__option__lease_time__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 6 bytes (code + len + 4-byte value).

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__field(self) -> None:
        """
        Ensure the 'lease_time' field reflects the constructor argument.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            self._option.lease_time,
            self._results["lease_time"],
            msg=f"Unexpected 'lease_time' for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__type(self) -> None:
        """
        Ensure the 'type' field is always LEASE_TIME.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            self._option.type,
            Dhcp4OptionType.LEASE_TIME,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__lease_time__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            Dhcp4OptionLeaseTime.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 IP Address Lease Time option (zero).",
            "_args": [b"\x33\x04\x00\x00\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=0),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one minute).",
            "_args": [b"\x33\x04\x00\x00\x00\x3c" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=60),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one day).",
            "_args": [b"\x33\x04\x00\x01\x51\x80" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=86400),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (max uint32, infinite lease).",
            "_args": [b"\x33\x04\xff\xff\xff\xff" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=UINT_32__MAX),
            },
        },
    ]
)
class TestDhcp4OptionLeaseTimeParser(TestCase):
    """
    The DHCPv4 IP Address Lease Time option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__lease_time__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        option = Dhcp4OptionLeaseTime.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionLeaseTimeParserErrors(TestCase):
    """
    The DHCPv4 IP Address Lease Time option parser error tests.
    """

    def test__dhcp4__option__lease_time__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionLeaseTime.from_buffer(b"\x33")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 IP Address Lease Time option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__lease_time__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 51.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionLeaseTime.from_buffer(b"\xfe\x04\x00\x00\x00\x3c")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 IP Address Lease Time option type must be {Dhcp4OptionType.LEASE_TIME!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__lease_time__bad_length_field(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        option length is not 4.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionLeaseTime.from_buffer(b"\x33\x03\x00\x00\x3c")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 IP Address Lease Time option length value must be 6 bytes. Got: 5",
            msg="Unexpected bad-length-field integrity message.",
        )

    def test__dhcp4__option__lease_time__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionLeaseTime.from_buffer(b"\x33\x04")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 IP Address Lease Time option length value must be "
            "less than or equal to the length of provided bytes (2). Got: 6",
            msg="Unexpected truncated-buffer integrity message.",
        )


class TestDhcp4OptionLeaseTimeBehavior(TestCase):
    """
    The DHCPv4 IP Address Lease Time option behavioral tests.
    """

    def test__dhcp4__option__lease_time__equality(self) -> None:
        """
        Ensure two options with equal 'lease_time' compare equal.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertEqual(
            Dhcp4OptionLeaseTime(3600),
            Dhcp4OptionLeaseTime(3600),
            msg="Options with identical lease_time must compare equal.",
        )

    def test__dhcp4__option__lease_time__inequality(self) -> None:
        """
        Ensure two options with different 'lease_time' compare unequal.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        self.assertNotEqual(
            Dhcp4OptionLeaseTime(3600),
            Dhcp4OptionLeaseTime(7200),
            msg="Options with different lease_time must not compare equal.",
        )

    def test__dhcp4__option__lease_time__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        option = Dhcp4OptionLeaseTime(60)

        with self.assertRaises(FrozenInstanceError):
            option.lease_time = 120  # type: ignore[misc]

    def test__dhcp4__option__lease_time__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §9.2 (IP Address Lease Time option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionLeaseTime(  # type: ignore[call-arg]
                type=Dhcp4OptionType.LEASE_TIME,
                lease_time=60,
            )
