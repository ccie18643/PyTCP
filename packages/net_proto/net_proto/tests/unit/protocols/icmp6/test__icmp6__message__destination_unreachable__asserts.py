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
Module contains tests for the ICMPv6 Destination Unreachable message
assembler & parser argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__destination_unreachable__asserts.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto import (
    ICMP6__DESTINATION_UNREACHABLE__LEN,
    IP6__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
)


class TestIcmp6MessageDestinationUnreachableAsserts(TestCase):
    """
    The ICMPv6 Destination Unreachable message constructor argument
    assert tests.
    """

    def setUp(self) -> None:
        """
        Build a valid kwargs baseline used as the starting point for every
        negative/positive boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6DestinationUnreachableCode.NO_ROUTE,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp6__message__destination_unreachable__code__not_Icmp6DestinationUnreachableCode(self) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message constructor rejects
        a 'code' argument that is not an Icmp6DestinationUnreachableCode.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self._kwargs["code"] = value = "not an Icmp6DestinationUnreachableCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6DestinationUnreachableCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp6__message__destination_unreachable__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message constructor rejects
        a 'cksum' argument below the 16-bit unsigned minimum.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp6__message__destination_unreachable__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message constructor rejects
        a 'cksum' argument above the 16-bit unsigned maximum.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp6__message__destination_unreachable__data__not_bytes(self) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message constructor rejects
        a 'data' argument that is neither bytes nor memoryview.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self._kwargs["data"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(value)!r}",
            msg="Unexpected 'data' type assert message.",
        )

    def test__icmp6__message__destination_unreachable__data_len__over_max(self) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message constructor rejects
        a 'data' argument whose length exceeds IP6__PAYLOAD__MAX_LEN minus
        the 8-byte Destination Unreachable header.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        value = IP6__PAYLOAD__MAX_LEN - ICMP6__DESTINATION_UNREACHABLE__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP6__PAYLOAD__MAX_LEN - ICMP6__DESTINATION_UNREACHABLE__LEN}. "
                f"Got: {value!r}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp6__message__destination_unreachable__all_codes_accepted(self) -> None:
        """
        Ensure every Icmp6DestinationUnreachableCode value is accepted by
        the message constructor.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        for code in Icmp6DestinationUnreachableCode:
            with self.subTest(code=code):
                kwargs = {**self._kwargs, "code": code}
                message = Icmp6MessageDestinationUnreachable(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} must be accepted verbatim.",
                )


class TestIcmp6MessageDestinationUnreachableFromBufferAsserts(TestCase):
    """
    The ICMPv6 Destination Unreachable message 'from_buffer()' assert tests.
    """

    def test__icmp6__message__destination_unreachable__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp6MessageDestinationUnreachable.from_buffer()' refuses
        to parse a buffer whose first byte (ICMPv6 'type') is not
        DESTINATION_UNREACHABLE (1).

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageDestinationUnreachable.from_buffer(
                # ICMPv6 (wrong type for Destination Unreachable)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Reserved : 0x00000000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.DESTINATION_UNREACHABLE: 1>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp6__message__destination_unreachable__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp6MessageDestinationUnreachable.from_buffer()' accepts a
        buffer whose first byte is DESTINATION_UNREACHABLE (1) and returns
        a concrete message instance.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        message = Icmp6MessageDestinationUnreachable.from_buffer(
            # ICMPv6 Destination Unreachable (minimal, zero-length data)
            #   Type     : 1 (Destination Unreachable)
            #   Code     : 0 (No Route)
            #   Checksum : 0x0000
            #   Reserved : 0x00000000
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp6MessageDestinationUnreachable,
            msg="from_buffer() must return an Icmp6MessageDestinationUnreachable instance.",
        )
