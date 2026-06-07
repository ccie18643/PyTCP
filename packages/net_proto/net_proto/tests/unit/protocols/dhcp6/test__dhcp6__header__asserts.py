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
This module contains tests for the DHCPv6 header fields and asserts.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__header__asserts.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_proto import (
    DHCP6__HEADER__LEN,
    UINT_24__MAX,
    UINT_24__MIN,
    Dhcp6Header,
    Dhcp6MessageType,
)


class TestDhcp6HeaderAsserts(TestCase):
    """
    The DHCPv6 header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv6 header constructor.
        """

        self._kwargs: dict[str, Any] = {
            "msg_type": Dhcp6MessageType.SOLICIT,
            "xid": 0x123456,
        }

    def test__dhcp6__header__default_accepted(self) -> None:
        """
        Ensure the DHCPv6 header constructor accepts the minimal valid field
        set and reports the canonical 4-byte length.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        header = Dhcp6Header(**self._kwargs)

        self.assertEqual(
            len(header),
            DHCP6__HEADER__LEN,
            msg="A minimal valid DHCPv6 header must be 4 bytes long.",
        )

    def test__dhcp6__header__msg_type__not_Dhcp6MessageType(self) -> None:
        """
        Ensure the DHCPv6 header constructor raises an exception when the
        provided 'msg_type' argument is not a Dhcp6MessageType.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self._kwargs["msg_type"] = value = "not a Dhcp6MessageType"

        with self.assertRaises(AssertionError) as error:
            Dhcp6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'msg_type' field must be a Dhcp6MessageType. Got: {type(value)!r}",
            msg="Unexpected 'msg_type' assert message.",
        )

    def test__dhcp6__header__xid__under_min(self) -> None:
        """
        Ensure the DHCPv6 header constructor raises an exception when the
        provided 'xid' argument is lower than the minimum supported value.

        Reference: RFC 8415 §8 (transaction-id field).
        """

        self._kwargs["xid"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'xid' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'xid' under-min assert message.",
        )

    def test__dhcp6__header__xid__over_max(self) -> None:
        """
        Ensure the DHCPv6 header constructor raises an exception when the
        provided 'xid' argument is higher than the maximum supported value.

        Reference: RFC 8415 §8 (transaction-id field).
        """

        self._kwargs["xid"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'xid' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'xid' over-max assert message.",
        )

    def test__dhcp6__header__xid__at_max_accepted(self) -> None:
        """
        Ensure the DHCPv6 header constructor accepts 'xid' of exactly the
        maximum 24-bit value.

        Reference: RFC 8415 §8 (transaction-id field).
        """

        self._kwargs["xid"] = UINT_24__MAX

        header = Dhcp6Header(**self._kwargs)

        self.assertEqual(
            header.xid,
            UINT_24__MAX,
            msg="'xid' of exactly UINT_24__MAX must be accepted.",
        )


class TestDhcp6HeaderOperation(TestCase):
    """
    The DHCPv6 header construction, equality, and buffer-protocol tests.
    """

    def _valid_kwargs(self) -> dict[str, Any]:
        """
        Return a reference set of valid DHCPv6 header constructor kwargs.
        """

        return {
            "msg_type": Dhcp6MessageType.SOLICIT,
            "xid": 0xAABBCC,
        }

    def test__dhcp6__header__construction(self) -> None:
        """
        Ensure a valid DHCPv6 header instance can be constructed and its fields
        are exposed exactly as provided.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        kwargs = self._valid_kwargs()

        header = Dhcp6Header(**kwargs)

        self.assertEqual(header.msg_type, kwargs["msg_type"], msg="Unexpected 'msg_type'.")
        self.assertEqual(header.xid, kwargs["xid"], msg="Unexpected 'xid'.")

    def test__dhcp6__header__len(self) -> None:
        """
        Ensure 'len()' on the header returns the canonical 4-byte size.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        header = Dhcp6Header(**self._valid_kwargs())

        self.assertEqual(
            len(header),
            DHCP6__HEADER__LEN,
            msg="DHCPv6 header length must be 4 bytes.",
        )

    def test__dhcp6__header__buffer_protocol(self) -> None:
        """
        Ensure the DHCPv6 header buffer representation matches the wire format.

        The DHCPv6 message header [RFC 8415] is laid out as:
          msg-type        : 1 (SOLICIT)
          transaction-id  : 0xAABBCC

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        header = Dhcp6Header(msg_type=Dhcp6MessageType.SOLICIT, xid=0xAABBCC)

        frame = bytes(memoryview(header))

        self.assertEqual(len(frame), DHCP6__HEADER__LEN, msg="Buffer must be 4 bytes long.")
        self.assertEqual(frame, b"\x01\xaa\xbb\xcc", msg="Unexpected msg-type/transaction-id bytes.")

    def test__dhcp6__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent header.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        original = Dhcp6Header(**self._valid_kwargs())

        rebuilt = Dhcp6Header.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )

    def test__dhcp6__header__from_buffer_consumes_prefix(self) -> None:
        """
        Ensure 'from_buffer()' reads only the first DHCP6__HEADER__LEN bytes and
        ignores any trailing options data.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        original = Dhcp6Header(**self._valid_kwargs())
        padded = bytes(memoryview(original)) + b"\xde\xad\xbe\xef"

        rebuilt = Dhcp6Header.from_buffer(padded)

        self.assertEqual(
            rebuilt,
            original,
            msg="Trailing bytes must not affect from_buffer output.",
        )

    def test__dhcp6__header__from_buffer_tolerates_unknown_msg_type(self) -> None:
        """
        Ensure 'from_buffer()' materialises an unknown 'msg-type' wire value as
        an UNKNOWN ProtoEnum member rather than raising, leaving the rejection
        to the parser sanity stage.

        Reference: RFC 8415 §7.3 (message type registry; unknown handling).
        """

        rebuilt = Dhcp6Header.from_buffer(b"\xff\x00\x00\x01")

        self.assertTrue(
            rebuilt.msg_type.is_unknown,
            msg="An unknown 'msg-type' wire value must materialise as UNKNOWN.",
        )
        self.assertEqual(
            int(rebuilt.msg_type),
            0xFF,
            msg="The unknown 'msg-type' must preserve its wire value.",
        )

    def test__dhcp6__header__equality(self) -> None:
        """
        Ensure two DHCPv6 headers with identical field values compare equal.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        kwargs = self._valid_kwargs()

        self.assertEqual(
            Dhcp6Header(**kwargs),
            Dhcp6Header(**kwargs),
            msg="Equal field sets must compare equal.",
        )

    def test__dhcp6__header__inequality_on_msg_type(self) -> None:
        """
        Ensure headers differing only in 'msg_type' compare unequal.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertNotEqual(
            Dhcp6Header(msg_type=Dhcp6MessageType.SOLICIT, xid=0xAABBCC),
            Dhcp6Header(msg_type=Dhcp6MessageType.REQUEST, xid=0xAABBCC),
            msg="Headers differing in 'msg_type' must not compare equal.",
        )

    def test__dhcp6__header__is_hashable(self) -> None:
        """
        Ensure DHCPv6 headers can be used as keys in a set/dict.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        header = Dhcp6Header(**self._valid_kwargs())

        self.assertIn(header, {header}, msg="DHCPv6 header must be hashable.")

    def test__dhcp6__header__is_frozen(self) -> None:
        """
        Ensure DHCPv6 header fields cannot be mutated after construction.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        header = Dhcp6Header(**self._valid_kwargs())

        with self.assertRaises(FrozenInstanceError):
            header.xid = 99  # type: ignore[misc]

    def test__dhcp6__header__rejects_positional_args(self) -> None:
        """
        Ensure the DHCPv6 header constructor rejects positional arguments.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        with self.assertRaises(TypeError):
            Dhcp6Header(  # type: ignore[misc]
                Dhcp6MessageType.SOLICIT,
                0xAABBCC,
            )
