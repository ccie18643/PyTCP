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
Module contains tests for the ICMPv6 unknown message assembler & parser asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__unknown__asserts.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6Code,
    Icmp6MessageUnknown,
    Icmp6Type,
    inet_cksum,
)


class TestIcmp6MessageUnknownAsserts(TestCase):
    """
    The ICMPv6 unknown message constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (unknown type 255, unknown code 255)
        used as the starting point for each negative test.
        """

        self._kwargs: dict[str, Any] = {
            "type": Icmp6Type.from_int(255),
            "code": Icmp6Code.from_int(255),
            "cksum": 0,
            "data": b"",
        }

    def test__icmp6__message__unknown__type__not_Icmp6Type(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor rejects a non-Icmp6Type
        'type' argument with a precise AssertionError.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["type"] = value = "not an Icmp6Type"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp6Type. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message.",
        )

    def test__icmp6__message__unknown__code__not_Icmp6Code(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor rejects a non-Icmp6Code
        'code' argument with a precise AssertionError.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["code"] = value = "not an Icmp6Code"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6Code. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp6__message__unknown__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor rejects a 'cksum'
        argument below the 16-bit unsigned minimum.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp6__message__unknown__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor rejects a 'cksum'
        argument above the 16-bit unsigned maximum.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp6__message__unknown__cksum__min_accepted(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor accepts the minimum
        16-bit unsigned 'cksum' value (0).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["cksum"] = UINT_16__MIN

        message = Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            message.cksum,
            UINT_16__MIN,
            msg="'cksum' at the lower bound must be accepted verbatim.",
        )

    def test__icmp6__message__unknown__cksum__max_accepted(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor accepts the maximum
        16-bit unsigned 'cksum' value (0xFFFF).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["cksum"] = UINT_16__MAX

        message = Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            message.cksum,
            UINT_16__MAX,
            msg="'cksum' at the upper bound must be accepted verbatim.",
        )

    def test__icmp6__message__unknown__data__not_bytes(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor rejects a 'data'
        argument that is not a bytes/bytearray/memoryview buffer.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["data"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be a bytes, bytearray or memoryview. Got: {type(value)!r}",
            msg="Unexpected 'data' type assert message.",
        )

    def test__icmp6__message__unknown__data__bytearray_accepted(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor accepts a bytearray
        'data' argument (the Buffer protocol allows mutable buffers too).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["data"] = bytearray(b"payload")

        message = Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            b"payload",
            msg="bytearray 'data' must be preserved verbatim.",
        )

    def test__icmp6__message__unknown__data__memoryview_accepted(self) -> None:
        """
        Ensure the ICMPv6 unknown message constructor accepts a memoryview
        'data' argument.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self._kwargs["data"] = memoryview(b"payload")

        message = Icmp6MessageUnknown(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            b"payload",
            msg="memoryview 'data' must be preserved verbatim.",
        )


class TestIcmp6MessageUnknownParserAsserts(TestCase):
    """
    The ICMPv6 unknown message 'from_buffer()' assert tests.
    """

    def test__icmp6__message__unknown__from_buffer__known_type_rejected(self) -> None:
        """
        Ensure 'Icmp6MessageUnknown.from_buffer()' refuses to construct an
        unknown-message wrapper around a frame whose 'type' byte corresponds
        to one of the known ICMPv6 types. That dispatch branch belongs to the
        concrete message class, not the unknown-message fallback.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        for type_value in Icmp6Type.get_known_values():
            with self.subTest(type_value=type_value):
                buffer = bytearray(
                    # ICMPv6 Known Type Template
                    #   Type     : set below
                    #   Code     : 0
                    #   Checksum : computed below
                    #   Reserved : 0x00000000
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                )
                buffer[0] = type_value
                buffer[2:4] = inet_cksum(buffer).to_bytes(2)

                with self.assertRaises(AssertionError) as error:
                    Icmp6MessageUnknown.from_buffer(buffer)

                self.assertEqual(
                    str(error.exception),
                    f"The 'type' field must not be known. Got: {Icmp6Type.from_int(type_value)!r}",
                    msg=f"Unexpected assert message for known type {type_value}.",
                )

    def test__icmp6__message__unknown__from_buffer__unknown_type_accepted(self) -> None:
        """
        Ensure 'Icmp6MessageUnknown.from_buffer()' constructs a proper unknown
        message when the 'type' byte is outside the known set (255 here).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        buffer = bytearray(
            # ICMPv6 Unknown Type Template
            #   Type     : 255 (unknown)
            #   Code     : 255 (unknown)
            #   Checksum : 0x0000 (irrelevant for from_buffer())
            #   Reserved : 0x00000000
            b"\xff\xff\x00\x00\x00\x00\x00\x00"
        )

        message = Icmp6MessageUnknown.from_buffer(buffer)

        self.assertEqual(
            message.type,
            Icmp6Type.from_int(255),
            msg="Unknown 'type' byte must round-trip via from_buffer().",
        )
        self.assertEqual(
            message.code,
            Icmp6Code.from_int(255),
            msg="Unknown 'code' byte must round-trip via from_buffer().",
        )
