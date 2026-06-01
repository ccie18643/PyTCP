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
Module contains tests for the ICMPv4 Destination Unreachable message
assembler & parser asserts.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__destination_unreachable__asserts.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto import (
    ICMP4__DESTINATION_UNREACHABLE__LEN,
    IP4__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
)
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN, IP4__MIN_MTU


class TestIcmp4MessageDestinationUnreachableAsserts(TestCase):
    """
    The ICMPv4 Destination Unreachable message constructor argument assert
    tests.
    """

    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (code=NETWORK, no MTU) used as the
        starting point for every negative/positive boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp4DestinationUnreachableCode.NETWORK,
            "mtu": None,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp4__message__destination_unreachable__code__not_Icmp4DestinationUnreachableCode(self) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message constructor rejects
        a 'code' argument that is not an Icmp4DestinationUnreachableCode.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        self._kwargs["code"] = value = "not an Icmp4DestinationUnreachableCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4DestinationUnreachableCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp4__message__destination_unreachable__frag_no_mtu(self) -> None:
        """
        Ensure the constructor rejects FRAGMENTATION_NEEDED with no MTU
        (mtu=None — the most common mistake that the validator catches).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        self._kwargs["code"] = Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        self._kwargs["mtu"] = value = None

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'mtu' required-when-FRAG assert message.",
        )

    def test__icmp4__message__destination_unreachable__no_frag_mtu(self) -> None:
        """
        Ensure the constructor rejects a non-None MTU when the code is
        anything other than FRAGMENTATION_NEEDED. The previous testslide
        version looped over codes but never actually wrote the loop variable
        into kwargs; here we set both and assert via subTest for every
        non-FRAG code value.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        mtu_value = 1500

        for code in Icmp4DestinationUnreachableCode:
            if code == Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
                continue

            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code, mtu=mtu_value)
                with self.assertRaises(AssertionError) as error:
                    Icmp4MessageDestinationUnreachable(**kwargs)
                self.assertEqual(
                    str(error.exception),
                    f"The 'mtu' field must not be set. Got: {mtu_value}",
                    msg=f"Unexpected 'mtu must not be set' assert for code {code!r}.",
                )

    def test__icmp4__message__destination_unreachable__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the 16-bit
        unsigned minimum.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp4__message__destination_unreachable__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the 16-bit
        unsigned maximum.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp4__message__destination_unreachable__mtu__under_min(self) -> None:
        """
        Ensure the constructor rejects an 'mtu' argument below the 16-bit
        unsigned minimum (code must be FRAGMENTATION_NEEDED for this branch
        of the validator to fire).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        self._kwargs["code"] = Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        self._kwargs["mtu"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'mtu' lower-bound assert message.",
        )

    def test__icmp4__message__destination_unreachable__mtu__over_max(self) -> None:
        """
        Ensure the constructor rejects an 'mtu' argument above the 16-bit
        unsigned maximum.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        self._kwargs["code"] = Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        self._kwargs["mtu"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'mtu' upper-bound assert message.",
        )

    def test__icmp4__message__destination_unreachable__data_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument whose length exceeds
        IP4__PAYLOAD__MAX_LEN minus the 8-byte Destination Unreachable
        header.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__DESTINATION_UNREACHABLE__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__DESTINATION_UNREACHABLE__LEN}. "
                f"Got: {value}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp4__message__destination_unreachable__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure the constructor silently truncates oversized 'data' to fit
        inside the minimum IPv4 MTU (IP4__MIN_MTU - IP4__HEADER__LEN -
        ICMP4__DESTINATION_UNREACHABLE__LEN = 548 bytes). Input below the
        over-max assert but above the truncation cap still succeeds — just
        with the tail snipped off — because RFC 792 only requires enough of
        the offending datagram to identify it.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__DESTINATION_UNREACHABLE__LEN
        self._kwargs["data"] = b"X" * (cap + 100)

        message = Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            len(message.data),
            cap,
            msg=f"'data' must be silently truncated to {cap} bytes (IP4__MIN_MTU minus headers).",
        )

    def test__icmp4__message__destination_unreachable__data_at_truncation_cap_kept_verbatim(self) -> None:
        """
        Ensure 'data' exactly at the truncation cap is kept verbatim (no
        bytes removed by the trailing object.__setattr__ slice).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__DESTINATION_UNREACHABLE__LEN
        payload = b"Y" * cap
        self._kwargs["data"] = payload

        message = Icmp4MessageDestinationUnreachable(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            payload,
            msg="'data' at the truncation cap must be kept verbatim.",
        )

    def test__icmp4__message__destination_unreachable__non_frag_codes_without_mtu_accepted(self) -> None:
        """
        Ensure the constructor accepts every non-FRAGMENTATION_NEEDED code
        when 'mtu' is None (the canonical Destination Unreachable wire
        shape).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        for code in Icmp4DestinationUnreachableCode:
            if code == Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
                continue

            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code, mtu=None)
                message = Icmp4MessageDestinationUnreachable(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} with mtu=None must be accepted verbatim.",
                )


class TestIcmp4MessageDestinationUnreachableFromBufferAsserts(TestCase):
    """
    The ICMPv4 Destination Unreachable message 'from_buffer()' assert tests.
    """

    def test__icmp4__message__destination_unreachable__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp4MessageDestinationUnreachable.from_buffer()' refuses to
        parse a buffer whose first byte (ICMPv4 'type') is not
        DESTINATION_UNREACHABLE (3).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageDestinationUnreachable.from_buffer(
                # ICMPv4 (wrong type for Destination Unreachable)
                #   Type     : 255 (Unknown)
                #   Code     : 0 (Network)
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Rest     : 0x00000000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp4Type.DESTINATION_UNREACHABLE: 3>. Got: <Icmp4Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp4__message__destination_unreachable__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp4MessageDestinationUnreachable.from_buffer()' accepts a
        buffer whose first byte is DESTINATION_UNREACHABLE (3) and returns
        a concrete Destination Unreachable message.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 fields).
        """

        message = Icmp4MessageDestinationUnreachable.from_buffer(
            # ICMPv4 Destination Unreachable (minimal, code=NETWORK)
            #   Type     : 3 (Destination Unreachable)
            #   Code     : 0 (Network)
            #   Checksum : 0x0000
            #   Rest     : 0x00000000
            b"\x03\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp4MessageDestinationUnreachable,
            msg="from_buffer() must return an Icmp4MessageDestinationUnreachable instance.",
        )
