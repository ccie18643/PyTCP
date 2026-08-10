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
Module contains tests for the ICMPv6 Time Exceeded message constructor
asserts and 'from_buffer()' invariants.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__time_exceeded__asserts.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    IP6__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6MessageTimeExceeded,
    Icmp6TimeExceededCode,
)
from net_proto.protocols.icmp6.message.icmp6__message__time_exceeded import (
    ICMP6__TIME_EXCEEDED__LEN,
)
from net_proto.protocols.ip6.ip6__header import IP6__HEADER__LEN, IP6__MIN_MTU


class TestIcmp6MessageTimeExceededAsserts(TestCase):
    """
    The ICMPv6 Time Exceeded message constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (code=HOP_LIMIT_EXCEEDED_IN_TRANSIT,
        no data).
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6TimeExceededCode.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp6__message__time_exceeded__code__not_Icmp6TimeExceededCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument that is not an
        Icmp6TimeExceededCode.

        Reference: RFC 4443 §3.3 (Time Exceeded codes 0/1 only).
        """

        self._kwargs["code"] = value = "not an Icmp6TimeExceededCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6TimeExceededCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp6__message__time_exceeded__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the
        16-bit unsigned minimum.

        Reference: RFC 4443 §2.1 (ICMPv6 message header checksum is
        16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp6__message__time_exceeded__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the
        16-bit unsigned maximum.

        Reference: RFC 4443 §2.1 (ICMPv6 message header checksum is
        16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp6__message__time_exceeded__data_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument whose length
        exceeds IP6__PAYLOAD__MAX_LEN minus the 8-byte Time Exceeded
        header.

        Reference: RFC 4443 §3.3 (Time Exceeded carries as much of the
        invoking packet as fits in MIN_MTU).
        """

        value = IP6__PAYLOAD__MAX_LEN - ICMP6__TIME_EXCEEDED__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP6__PAYLOAD__MAX_LEN - ICMP6__TIME_EXCEEDED__LEN}. "
                f"Got: {value!r}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp6__message__time_exceeded__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure the constructor silently truncates oversized 'data' to fit
        inside the IPv6 minimum MTU (1280 - 40 - 8 = 1232 bytes).

        Reference: RFC 4443 §3.3 (Time Exceeded data field MUST NOT
        exceed MIN_MTU after the IPv6 + ICMPv6 headers).
        """

        cap = IP6__MIN_MTU - IP6__HEADER__LEN - ICMP6__TIME_EXCEEDED__LEN
        self._kwargs["data"] = b"X" * (cap + 100)

        message = Icmp6MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            len(message.data),
            cap,
            msg=f"'data' must be silently truncated to {cap} bytes.",
        )

    def test__icmp6__message__time_exceeded__both_codes_accepted(self) -> None:
        """
        Ensure the constructor accepts both RFC 4443 codes (0 = hop
        limit exceeded in transit, 1 = fragment reassembly time
        exceeded).

        Reference: RFC 4443 §3.3 (Time Exceeded codes 0 and 1).
        """

        for code in Icmp6TimeExceededCode:
            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code)
                message = Icmp6MessageTimeExceeded(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} must be accepted verbatim.",
                )


class TestIcmp6MessageTimeExceededFromBufferAsserts(TestCase):
    """
    The ICMPv6 Time Exceeded message 'from_buffer()' assert tests.
    """

    def test__icmp6__message__time_exceeded__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp6MessageTimeExceeded.from_buffer()' refuses to parse
        a buffer whose first byte is not TIME_EXCEEDED (3).

        Reference: RFC 4443 §3.3 (Time Exceeded type field is 3).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageTimeExceeded.from_buffer(
                # ICMPv6 (wrong type for Time Exceeded)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Unused   : 0x00000000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.TIME_EXCEEDED: 3>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp6__message__time_exceeded__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp6MessageTimeExceeded.from_buffer()' accepts a buffer
        whose first byte is TIME_EXCEEDED (3).

        Reference: RFC 4443 §3.3 (Time Exceeded type field is 3).
        """

        message = Icmp6MessageTimeExceeded.from_buffer(
            # ICMPv6 Time Exceeded (minimal, code=HOP_LIMIT_EXCEEDED_IN_TRANSIT)
            #   Type     : 3 (Time Exceeded)
            #   Code     : 0 (Hop Limit Exceeded In Transit)
            #   Checksum : 0x0000
            #   Unused   : 0x00000000
            b"\x03\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp6MessageTimeExceeded,
            msg="from_buffer() must return an Icmp6MessageTimeExceeded instance.",
        )
