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
Module contains tests for the ICMPv4 Redirect message constructor
asserts and 'from_buffer()' invariants.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__redirect__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    IP4__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4MessageRedirect,
    Icmp4RedirectCode,
)
from net_proto.protocols.icmp4.message.icmp4__message__redirect import (
    ICMP4__REDIRECT__LEN,
)
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN, IP4__MIN_MTU


class TestIcmp4MessageRedirectAsserts(TestCase):
    """
    The ICMPv4 Redirect message constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (code=HOST, gateway=10.0.1.1, no
        data) used as the starting point for every negative/positive
        boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp4RedirectCode.HOST,
            "cksum": 0,
            "gateway": Ip4Address("10.0.1.1"),
            "data": b"",
        }

    def test__icmp4__message__redirect__code__not_Icmp4RedirectCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument that is not an
        Icmp4RedirectCode.

        Reference: RFC 792 (Redirect codes 0..3 only).
        """

        self._kwargs["code"] = value = "not an Icmp4RedirectCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4RedirectCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp4__message__redirect__gateway__not_Ip4Address(self) -> None:
        """
        Ensure the constructor rejects a 'gateway' argument that is not
        an Ip4Address.

        Reference: RFC 792 (Redirect gateway is an IPv4 address).
        """

        self._kwargs["gateway"] = value = "10.0.1.1"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'gateway' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'gateway' type assert message.",
        )

    def test__icmp4__message__redirect__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the 16-bit
        unsigned minimum.

        Reference: RFC 792 (ICMP message header checksum is 16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp4__message__redirect__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the 16-bit
        unsigned maximum.

        Reference: RFC 792 (ICMP message header checksum is 16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp4__message__redirect__data_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument whose length
        exceeds IP4__PAYLOAD__MAX_LEN minus the 8-byte Redirect header.

        Reference: RFC 792 (Redirect carries Internet header + first 8
        octets of original datagram; total constrained by IPv4 max
        payload).
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__REDIRECT__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__REDIRECT__LEN}. "
                f"Got: {value}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp4__message__redirect__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure the constructor silently truncates oversized 'data' to fit
        inside the minimum IPv4 MTU.

        Reference: RFC 1812 §4.3.2.3 (576-byte cap on ICMP error message).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__REDIRECT__LEN
        self._kwargs["data"] = b"X" * (cap + 100)

        message = Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            len(message.data),
            cap,
            msg=f"'data' must be silently truncated to {cap} bytes (IP4__MIN_MTU minus headers).",
        )

    def test__icmp4__message__redirect__data_at_truncation_cap_kept_verbatim(self) -> None:
        """
        Ensure 'data' exactly at the truncation cap is kept verbatim (no
        bytes removed by the trailing object.__setattr__ slice).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__REDIRECT__LEN
        payload = b"Y" * cap
        self._kwargs["data"] = payload

        message = Icmp4MessageRedirect(**self._kwargs)

        self.assertEqual(
            bytes(message.data),
            payload,
            msg="'data' at the truncation cap must be kept verbatim.",
        )

    def test__icmp4__message__redirect__all_codes_accepted(self) -> None:
        """
        Ensure the constructor accepts all four RFC 792 codes (0 = net,
        1 = host, 2 = ToS+net, 3 = ToS+host).

        Reference: RFC 792 (Redirect codes 0..3).
        """

        for code in Icmp4RedirectCode:
            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code)
                message = Icmp4MessageRedirect(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} must be accepted verbatim.",
                )


class TestIcmp4MessageRedirectFromBufferAsserts(TestCase):
    """
    The ICMPv4 Redirect message 'from_buffer()' assert tests.
    """

    def test__icmp4__message__redirect__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp4MessageRedirect.from_buffer()' refuses to parse a
        buffer whose first byte (ICMPv4 'type') is not REDIRECT (5).

        Reference: RFC 792 (Redirect type field is 5).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageRedirect.from_buffer(
                # ICMPv4 (wrong type for Redirect)
                #   Type     : 255 (Unknown)
                #   Code     : 1 (Host)
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Gateway  : 0.0.0.0
                b"\xff\x01\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp4Type.REDIRECT: 5>. Got: <Icmp4Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp4__message__redirect__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp4MessageRedirect.from_buffer()' accepts a buffer whose
        first byte is REDIRECT (5) and returns a concrete Redirect message
        carrying the decoded gateway.

        Reference: RFC 792 (Redirect type field is 5, gateway address).
        """

        message = Icmp4MessageRedirect.from_buffer(
            # ICMPv4 Redirect (minimal, code=Host, gateway 10.0.1.1)
            #   Type     : 5 (Redirect)
            #   Code     : 1 (Host)
            #   Checksum : 0x0000
            #   Gateway  : 10.0.1.1
            b"\x05\x01\x00\x00\x0a\x00\x01\x01"
        )

        self.assertIsInstance(
            message,
            Icmp4MessageRedirect,
            msg="from_buffer() must return an Icmp4MessageRedirect instance.",
        )
        self.assertEqual(
            message.gateway,
            Ip4Address("10.0.1.1"),
            msg="from_buffer() must decode the gateway address.",
        )
