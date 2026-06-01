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
Module contains tests for the ICMPv4 Echo Request message assembler & parser
asserts.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__echo_request__asserts.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto import (
    ICMP4__ECHO_REQUEST__LEN,
    IP4__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4EchoRequestCode,
    Icmp4MessageEchoRequest,
)


class TestIcmp4MessageEchoRequestAsserts(TestCase):
    """
    The ICMPv4 Echo Request message constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Build a valid kwargs baseline used as the starting point for every
        negative/positive boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp4EchoRequestCode.DEFAULT,
            "cksum": 0,
            "id": 0,
            "seq": 0,
            "data": b"",
        }

    def test__icmp4__message__echo_request__code__not_Icmp4EchoRequestCode(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'code'
        argument that is not an Icmp4EchoRequestCode.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["code"] = value = "not an Icmp4EchoRequestCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4EchoRequestCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp4__message__echo_request__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'cksum'
        argument below the 16-bit unsigned minimum.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp4__message__echo_request__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'cksum'
        argument above the 16-bit unsigned maximum.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp4__message__echo_request__id__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects an 'id'
        argument below the 16-bit unsigned minimum.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["id"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'id' lower-bound assert message.",
        )

    def test__icmp4__message__echo_request__id__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects an 'id'
        argument above the 16-bit unsigned maximum.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["id"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'id' upper-bound assert message.",
        )

    def test__icmp4__message__echo_request__seq__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'seq'
        argument below the 16-bit unsigned minimum.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["seq"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'seq' lower-bound assert message.",
        )

    def test__icmp4__message__echo_request__seq__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'seq'
        argument above the 16-bit unsigned maximum.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["seq"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'seq' upper-bound assert message.",
        )

    def test__icmp4__message__echo_request__data__not_bytes(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'data'
        argument that is neither bytes nor memoryview.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        self._kwargs["data"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(value)!r}.",
            msg="Unexpected 'data' type assert message.",
        )

    def test__icmp4__message__echo_request__data_len__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor rejects a 'data'
        argument whose length exceeds IP4__PAYLOAD__MAX_LEN minus the 8-byte
        Echo Request header (i.e. the frame would no longer fit in an IPv4
        payload).

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN}. "
                f"Got: {value!r}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp4__message__echo_request__data_len__at_max_accepted(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor accepts a 'data'
        argument whose length is exactly IP4__PAYLOAD__MAX_LEN - header.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        max_len = IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN
        self._kwargs["data"] = b"X" * max_len

        message = Icmp4MessageEchoRequest(**self._kwargs)

        self.assertEqual(
            len(message.data),
            max_len,
            msg="'data' at the maximum length must be accepted verbatim.",
        )

    def test__icmp4__message__echo_request__id_seq_bounds_accepted(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor accepts 'id' and
        'seq' at the minimum (0) and maximum (0xFFFF) 16-bit unsigned values.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        for field_name in ("id", "seq"):
            for value in (UINT_16__MIN, UINT_16__MAX):
                with self.subTest(field_name=field_name, value=value):
                    kwargs = dict(self._kwargs, **{field_name: value})
                    message = Icmp4MessageEchoRequest(**kwargs)
                    self.assertEqual(
                        getattr(message, field_name),
                        value,
                        msg=f"'{field_name}' at bound {value} must be accepted verbatim.",
                    )


class TestIcmp4MessageEchoRequestFromBufferAsserts(TestCase):
    """
    The ICMPv4 Echo Request message 'from_buffer()' assert tests.
    """

    def test__icmp4__message__echo_request__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp4MessageEchoRequest.from_buffer()' refuses to parse a
        buffer whose first byte (ICMPv4 'type') is not ECHO_REQUEST.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageEchoRequest.from_buffer(
                # ICMPv4 (wrong type for Echo Request)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Id/Seq   : 0x0000/0x0000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp4Type.ECHO_REQUEST: 8>. Got: <Icmp4Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp4__message__echo_request__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp4MessageEchoRequest.from_buffer()' accepts a buffer whose
        first byte is ECHO_REQUEST (8) and returns a concrete request message.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 fields).
        """

        message = Icmp4MessageEchoRequest.from_buffer(
            # ICMPv4 Echo Request (minimal, zero-length data)
            #   Type     : 8 (Echo Request)
            #   Code     : 0 (Default)
            #   Checksum : 0x0000
            #   Id       : 0x0000
            #   Seq      : 0x0000
            b"\x08\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp4MessageEchoRequest,
            msg="from_buffer() must return an Icmp4MessageEchoRequest instance.",
        )
