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
Module contains tests for the ICMPv4 unknown message assembler & parser asserts.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__unknown__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4Code,
    Icmp4MessageUnknown,
    Icmp4Type,
    inet_cksum,
)


class TestIcmp4MessageUnknownAsserts(TestCase):
    """
    The ICMPv4 unknown message constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (unknown type 255, unknown code 255)
        used as the starting point for each negative test.
        """

        self._kwargs: dict[str, Any] = {
            "type": Icmp4Type.from_int(255),
            "code": Icmp4Code.from_int(255),
            "cksum": 0,
            "data": b"",
        }

    def test__icmp4__message__unknown__type__not_Icmp4Type(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor rejects a non-Icmp4Type
        'type' argument with a precise AssertionError.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["type"] = value = "not an Icmp4Type"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp4Type. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message.",
        )

    def test__icmp4__message__unknown__code__not_Icmp4Code(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor rejects a non-Icmp4Code
        'code' argument with a precise AssertionError.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["code"] = value = "not an Icmp4Code"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4Code. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp4__message__unknown__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor rejects a 'cksum'
        argument below the 16-bit unsigned minimum.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp4__message__unknown__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor rejects a 'cksum'
        argument above the 16-bit unsigned maximum.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp4__message__unknown__cksum__min_accepted(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor accepts the minimum
        16-bit unsigned 'cksum' value (0).

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["cksum"] = UINT_16__MIN

        message = Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            message.cksum,
            UINT_16__MIN,
            msg="'cksum' at the lower bound must be accepted verbatim.",
        )

    def test__icmp4__message__unknown__cksum__max_accepted(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor accepts the maximum
        16-bit unsigned 'cksum' value (0xFFFF).

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["cksum"] = UINT_16__MAX

        message = Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            message.cksum,
            UINT_16__MAX,
            msg="'cksum' at the upper bound must be accepted verbatim.",
        )

    def test__icmp4__message__unknown__data__not_bytes(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor rejects a 'data'
        argument that is not a bytes/bytearray/memoryview buffer.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["data"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be a bytes, bytearray or memoryview. Got: {type(value)!r}",
            msg="Unexpected 'data' type assert message.",
        )

    def test__icmp4__message__unknown__data__bytearray_accepted(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor accepts a bytearray
        'data' argument (the Buffer protocol allows mutable buffers too).

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["data"] = bytearray(b"payload")

        message = Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            b"payload",
            msg="bytearray 'data' must be preserved verbatim.",
        )

    def test__icmp4__message__unknown__data__memoryview_accepted(self) -> None:
        """
        Ensure the ICMPv4 unknown message constructor accepts a memoryview
        'data' argument.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        self._kwargs["data"] = memoryview(b"payload")

        message = Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            b"payload",
            msg="memoryview 'data' must be preserved verbatim.",
        )


class TestIcmp4MessageUnknownParserAsserts(TestCase):
    """
    The ICMPv4 unknown message 'from_buffer()' assert tests.
    """

    def test__icmp4__message__unknown__from_buffer__known_type_rejected(self) -> None:
        """
        Ensure 'Icmp4MessageUnknown.from_buffer()' refuses to construct an
        unknown-message wrapper around a frame whose 'type' byte corresponds
        to one of the known ICMPv4 types (0 = Echo Reply, 3 = Destination
        Unreachable, 8 = Echo Request). That dispatch branch belongs to the
        concrete message class, not the unknown-message fallback.

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        for type_value in Icmp4Type.get_known_values():
            with self.subTest(type_value=type_value):
                buffer = bytearray(
                    # ICMPv4 Known Type Template
                    #   Type     : set below (one of 0/3/8)
                    #   Code     : 0
                    #   Checksum : computed below
                    #   Rest     : 0x00000000
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                )
                buffer[0] = type_value
                buffer[2:4] = inet_cksum(buffer).to_bytes(2)

                with self.assertRaises(AssertionError) as error:
                    Icmp4MessageUnknown.from_buffer(buffer)

                self.assertEqual(
                    str(error.exception),
                    f"The 'type' field must not be known. Got: {Icmp4Type.from_int(type_value)!r}",
                    msg=f"Unexpected assert message for known type {type_value}.",
                )

    def test__icmp4__message__unknown__from_buffer__unknown_type_accepted(self) -> None:
        """
        Ensure 'Icmp4MessageUnknown.from_buffer()' constructs a proper unknown
        message when the 'type' byte is outside the known set (255 here).

        Reference: RFC 792 (ICMPv4 unknown-type message fields).
        """

        buffer = bytearray(
            # ICMPv4 Unknown Type Template
            #   Type     : 255 (unknown)
            #   Code     : 255 (unknown)
            #   Checksum : 0x0000 (irrelevant for from_buffer())
            #   Rest     : 0x00000000
            b"\xff\xff\x00\x00\x00\x00\x00\x00"
        )

        message = Icmp4MessageUnknown.from_buffer(buffer)

        self.assertEqual(
            message.type,
            Icmp4Type.from_int(255),
            msg="Unknown 'type' byte must round-trip via from_buffer().",
        )
        self.assertEqual(
            message.code,
            Icmp4Code.from_int(255),
            msg="Unknown 'code' byte must round-trip via from_buffer().",
        )
