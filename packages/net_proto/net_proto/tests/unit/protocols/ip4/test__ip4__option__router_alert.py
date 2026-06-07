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
Module contains tests for the IPv4 Router Alert option code (RFC 2113).

net_proto/tests/unit/protocols/ip4/test__ip4__option__router_alert.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    IP4__OPTION__ROUTER_ALERT__LEN,
    Ip4IntegrityError,
    Ip4OptionRouterAlert,
    Ip4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionRouterAlertAsserts(TestCase):
    """
    The IPv4 Router Alert option constructor argument assert tests.
    """

    def test__ip4__option__router_alert__value__under_min(self) -> None:
        """
        Ensure the IPv4 Router Alert option constructor rejects a
        negative 'value' (must be a 16-bit unsigned integer).

        Reference: RFC 2113 (Router Alert value field is 16-bit).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRouterAlert(value=-1)

        self.assertEqual(
            str(error.exception),
            "The 'value' field must be a 16-bit unsigned integer. Got: -1",
            msg="Unexpected assertion message for 'value' < 0.",
        )

    def test__ip4__option__router_alert__value__over_max(self) -> None:
        """
        Ensure the IPv4 Router Alert option constructor rejects a
        'value' above 0xFFFF.

        Reference: RFC 2113 (Router Alert value field is 16-bit).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRouterAlert(value=0x10000)

        self.assertEqual(
            str(error.exception),
            "The 'value' field must be a 16-bit unsigned integer. Got: 65536",
            msg="Unexpected assertion message for 'value' > 0xFFFF.",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 Router Alert with value=0 (canonical 'examine packet').",
            "_value": 0,
            "_results": {
                "__len__": 4,
                "__str__": "router_alert",
                "__repr__": "Ip4OptionRouterAlert(value=0)",
                # IPv4 Router Alert wire frame (4 bytes):
                #   Byte  0    : 0x94   -> type=Ip4OptionType.ROUTER_ALERT (148)
                #   Byte  1    : 0x04   -> len=4 (always)
                #   Bytes 2-3  : 0x0000 -> value=0 (examine packet)
                "__bytes__": b"\x94\x04\x00\x00",
            },
        },
        {
            "_description": "IPv4 Router Alert with value=42 (non-canonical, reserved range).",
            "_value": 42,
            "_results": {
                "__len__": 4,
                "__str__": "router_alert value=42",
                "__repr__": "Ip4OptionRouterAlert(value=42)",
                # IPv4 Router Alert wire frame (4 bytes):
                #   Byte  0    : 0x94   -> type=Ip4OptionType.ROUTER_ALERT (148)
                #   Byte  1    : 0x04   -> len=4
                #   Bytes 2-3  : 0x002a -> value=42
                "__bytes__": b"\x94\x04\x00\x2a",
            },
        },
        {
            "_description": "IPv4 Router Alert with value=0xFFFF (16-bit max boundary).",
            "_value": 0xFFFF,
            "_results": {
                "__len__": 4,
                "__str__": "router_alert value=65535",
                "__repr__": "Ip4OptionRouterAlert(value=65535)",
                # IPv4 Router Alert wire frame (4 bytes):
                #   Byte  0    : 0x94   -> type=Ip4OptionType.ROUTER_ALERT (148)
                #   Byte  1    : 0x04   -> len=4
                #   Bytes 2-3  : 0xffff -> value=65535 (UINT_16__MAX)
                "__bytes__": b"\x94\x04\xff\xff",
            },
        },
    ]
)
class TestIp4OptionRouterAlertAssembler(TestCase):
    """
    The IPv4 Router Alert option assembler tests.
    """

    _description: str
    _value: int
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an Ip4OptionRouterAlert from the parametrized 'value'.
        """

        self._option = Ip4OptionRouterAlert(value=self._value)

    def test__ip4__option__router_alert__len(self) -> None:
        """
        Ensure '__len__' reports the canonical 4-byte length —
        Router Alert is a fixed-size option.

        Reference: RFC 2113 (Router Alert is always 4 bytes).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected '__len__' for case: {self._description}",
        )

    def test__ip4__option__router_alert__str(self) -> None:
        """
        Ensure '__str__' renders 'router_alert' for the canonical
        value=0 case and 'router_alert value=N' for non-zero values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected '__str__' for case: {self._description}",
        )

    def test__ip4__option__router_alert__repr(self) -> None:
        """
        Ensure '__repr__' is the canonical dataclass form with
        'value' as the only visible field.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected '__repr__' for case: {self._description}",
        )

    def test__ip4__option__router_alert__bytes(self) -> None:
        """
        Ensure 'bytes()' serialises to the canonical RFC 2113 wire
        format: type=148 / len=4 / value (network byte order).

        Reference: RFC 2113 (Router Alert wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected 'bytes()' for case: {self._description}",
        )

    def test__ip4__option__router_alert__type(self) -> None:
        """
        Ensure the 'type' field is Ip4OptionType.ROUTER_ALERT (the
        wire value 148) regardless of constructor arguments.

        Reference: RFC 2113 (Router Alert type byte = 148).
        """

        self.assertIs(
            self._option.type,
            Ip4OptionType.ROUTER_ALERT,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ip4__option__router_alert__length(self) -> None:
        """
        Ensure the option's 'len' field equals the canonical 4-byte
        length on every case (Router Alert has no variable component).

        Reference: RFC 2113 (Router Alert length value is always 4).
        """

        self.assertEqual(
            self._option.len,
            IP4__OPTION__ROUTER_ALERT__LEN,
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__ip4__option__router_alert__roundtrip(self) -> None:
        """
        Ensure an option assembled to bytes and re-parsed via
        'from_buffer' equals the original — value, type, len all
        round-trip without loss.

        Reference: RFC 2113 (Router Alert wire format).
        """

        roundtripped = Ip4OptionRouterAlert.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            roundtripped,
            self._option,
            msg=f"Unexpected roundtrip result for case: {self._description}",
        )


class TestIp4OptionRouterAlertIntegrity(TestCase):
    """
    The IPv4 Router Alert option 'from_buffer' integrity-check tests.
    """

    def test__ip4__option__router_alert__integrity__length__not_4(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte is not exactly 4. RFC 2113 mandates a fixed
        4-byte length.

        Reference: RFC 2113 (Router Alert length must be 4).
        """

        # Bytes: 0x94=type, 0x06=len (wrong), 0x00 0x00=value, plus padding
        buffer = b"\x94\x06\x00\x00\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionRouterAlert.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Router Alert option length value must be 4 bytes. Got: 6",
            msg="Unexpected integrity-error message for length != 4.",
        )

    def test__ip4__option__router_alert__integrity__length__exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when an under-min
        buffer is provided (covers the assertion path before the
        length-byte check fires for length > buffer).

        Reference: RFC 2113 (Router Alert length must be 4).
        """

        # Bytes: 0x94=type, 0x04=len, but only 3 bytes total provided.
        buffer = b"\x94\x04\x00"

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRouterAlert.from_buffer(buffer)

        self.assertIn(
            "minimum length",
            str(error.exception),
            msg="Unexpected assertion message for under-min buffer.",
        )
