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
Module contains tests for the ICMPv4 Time Exceeded message constructor
asserts and 'from_buffer()' invariants.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__time_exceeded__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    IP4__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4MessageTimeExceeded,
    Icmp4TimeExceededCode,
)
from net_proto.protocols.icmp4.message.icmp4__message__time_exceeded import (
    ICMP4__TIME_EXCEEDED__LEN,
)
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN, IP4__MIN_MTU


class TestIcmp4MessageTimeExceededAsserts(TestCase):
    """
    The ICMPv4 Time Exceeded message constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (code=TTL_EXCEEDED_IN_TRANSIT, no
        data) used as the starting point for every negative/positive
        boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp4__message__time_exceeded__code__not_Icmp4TimeExceededCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument that is not an
        Icmp4TimeExceededCode.

        Reference: RFC 792 (Time Exceeded codes 0/1 only).
        """

        self._kwargs["code"] = value = "not an Icmp4TimeExceededCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4TimeExceededCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp4__message__time_exceeded__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the 16-bit
        unsigned minimum.

        Reference: RFC 792 (ICMP message header checksum is 16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp4__message__time_exceeded__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the 16-bit
        unsigned maximum.

        Reference: RFC 792 (ICMP message header checksum is 16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp4__message__time_exceeded__data_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument whose length
        exceeds IP4__PAYLOAD__MAX_LEN minus the 8-byte Time Exceeded
        header.

        Reference: RFC 792 (Time Exceeded carries Internet header + first
        8 octets of original datagram; total constrained by IPv4 max
        payload).
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__TIME_EXCEEDED__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__TIME_EXCEEDED__LEN}. "
                f"Got: {value}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp4__message__time_exceeded__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure the constructor silently truncates oversized 'data' to fit
        inside the minimum IPv4 MTU. Mirrors the Destination Unreachable
        truncation rule.

        Reference: RFC 1812 §4.3.2.3 (576-byte cap on ICMP error message).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__TIME_EXCEEDED__LEN
        self._kwargs["data"] = b"X" * (cap + 100)

        message = Icmp4MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            len(message.data),
            cap,
            msg=f"'data' must be silently truncated to {cap} bytes (IP4__MIN_MTU minus headers).",
        )

    def test__icmp4__message__time_exceeded__data_at_truncation_cap_kept_verbatim(self) -> None:
        """
        Ensure 'data' exactly at the truncation cap is kept verbatim (no
        bytes removed by the trailing object.__setattr__ slice).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__TIME_EXCEEDED__LEN
        payload = b"Y" * cap
        self._kwargs["data"] = payload

        message = Icmp4MessageTimeExceeded(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            payload,
            msg="'data' at the truncation cap must be kept verbatim.",
        )

    def test__icmp4__message__time_exceeded__both_codes_accepted(self) -> None:
        """
        Ensure the constructor accepts both RFC 792 codes (0 = TTL
        exceeded in transit, 1 = Fragment reassembly time exceeded).

        Reference: RFC 792 (Time Exceeded codes 0 and 1).
        """

        for code in Icmp4TimeExceededCode:
            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code)
                message = Icmp4MessageTimeExceeded(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} must be accepted verbatim.",
                )


class TestIcmp4MessageTimeExceededFromBufferAsserts(TestCase):
    """
    The ICMPv4 Time Exceeded message 'from_buffer()' assert tests.
    """

    def test__icmp4__message__time_exceeded__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp4MessageTimeExceeded.from_buffer()' refuses to parse
        a buffer whose first byte (ICMPv4 'type') is not TIME_EXCEEDED
        (11).

        Reference: RFC 792 (Time Exceeded type field is 11).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageTimeExceeded.from_buffer(
                # ICMPv4 (wrong type for Time Exceeded)
                #   Type     : 255 (Unknown)
                #   Code     : 0 (TTL Exceeded in Transit)
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Rest     : 0x00000000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp4Type.TIME_EXCEEDED: 11>. Got: <Icmp4Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp4__message__time_exceeded__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp4MessageTimeExceeded.from_buffer()' accepts a buffer
        whose first byte is TIME_EXCEEDED (11) and returns a concrete
        Time Exceeded message.

        Reference: RFC 792 (Time Exceeded type field is 11).
        """

        message = Icmp4MessageTimeExceeded.from_buffer(
            # ICMPv4 Time Exceeded (minimal, code=TTL_EXCEEDED_IN_TRANSIT)
            #   Type     : 11 (Time Exceeded)
            #   Code     : 0 (TTL Exceeded in Transit)
            #   Checksum : 0x0000
            #   Rest     : 0x00000000
            b"\x0b\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp4MessageTimeExceeded,
            msg="from_buffer() must return an Icmp4MessageTimeExceeded instance.",
        )
