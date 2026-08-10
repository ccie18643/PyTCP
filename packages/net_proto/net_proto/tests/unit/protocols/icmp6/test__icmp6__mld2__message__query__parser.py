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
Module contains tests for the ICMPv6 MLDv2 Query message (RX-only).

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__query__parser.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6Mld2MessageQuery,
)
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__query import (
    Icmp6Mld2QueryCode,
)

# ICMPv6 MLDv2 Query wire frame (60 bytes = 28-byte header + 2 × 16-byte
# source addresses):
#   Byte 0      : 0x82            -> type=MULTICAST_LISTENER_QUERY (130)
#   Byte 1      : 0x00            -> code=DEFAULT (0)
#   Bytes 2-3   : 0x1234          -> checksum
#   Bytes 4-5   : 0x2710          -> Maximum Response Code = 10000
#   Bytes 6-7   : 0x0000          -> Reserved
#   Bytes 8-23  : ff38::1234      -> Multicast Address
#   Byte 24     : 0x0a            -> Resv(0) S(1) QRV(2)  ->  s_flag=True, qrv=2
#   Byte 25     : 0x7d            -> QQIC = 125
#   Bytes 26-27 : 0x0002          -> Number of Sources = 2
#   Bytes 28-43 : 2001:db8::1     -> Source Address [1]
#   Bytes 44-59 : 2001:db8::2     -> Source Address [2]
_QUERY_FRAME = bytes.fromhex(
    "8200123427100000"
    "ff380000000000000000000000001234"
    "0a7d0002"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
)


class TestIcmp6Mld2MessageQueryAsserts(TestCase):
    """
    The ICMPv6 MLDv2 Query message constructor assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the MLDv2 Query message
        constructor so each test can override one field.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6Mld2QueryCode.DEFAULT,
            "maximum_response_code": 10000,
            "multicast_address": Ip6Address("ff38::1234"),
        }

    def test__icmp6__mld2__message__query__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions.

        Reference: RFC 3810 §5.1 (MLDv2 Query wire format).
        """

        message = Icmp6Mld2MessageQuery(**self._kwargs)

        self.assertEqual(
            len(message),
            28,
            msg="Default MLDv2 Query (no sources) must be 28 bytes.",
        )

    def test__icmp6__mld2__message__query__code__not_Icmp6Mld2QueryCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' that is not an
        Icmp6Mld2QueryCode.

        Reference: RFC 3810 §5.1 (MLDv2 Query code is 0).
        """

        self._kwargs["code"] = value = "not a code"

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageQuery(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6Mld2QueryCode. Got: {type(value)!r}",
            msg="Unexpected assertion message for a non-Icmp6Mld2QueryCode 'code'.",
        )

    def test__icmp6__mld2__message__query__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' above UINT_16__MAX.

        Reference: RFC 3810 §5.1 (Checksum is a 16-bit field).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageQuery(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected assertion message for 'cksum' over UINT_16__MAX.",
        )

    def test__icmp6__mld2__message__query__maximum_response_code__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'maximum_response_code' above
        UINT_16__MAX.

        Reference: RFC 3810 §5.1 (Maximum Response Code is a 16-bit field).
        """

        self._kwargs["maximum_response_code"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageQuery(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'maximum_response_code' field must be uint16. Got: {value!r}",
            msg="Unexpected assertion message for 'maximum_response_code' over UINT_16__MAX.",
        )

    def test__icmp6__mld2__message__query__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' below UINT_16__MIN.

        Reference: RFC 3810 §5.1 (Checksum is a 16-bit field).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageQuery(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected assertion message for 'cksum' under UINT_16__MIN.",
        )

    def test__icmp6__mld2__message__query__multicast_address__not_Ip6Address(self) -> None:
        """
        Ensure the constructor rejects a 'multicast_address' that is not
        an Ip6Address.

        Reference: RFC 3810 §5.1 (Multicast Address is a 128-bit field).
        """

        self._kwargs["multicast_address"] = value = "ff38::1234"

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageQuery(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'multicast_address' field must be an Ip6Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for a non-Ip6Address 'multicast_address'.",
        )


class TestIcmp6Mld2MessageQueryParser(TestCase):
    """
    The ICMPv6 MLDv2 Query message parser (from_buffer / integrity) tests.
    """

    def test__icmp6__mld2__message__query__from_buffer_fields(self) -> None:
        """
        Ensure 'from_buffer()' decodes every header field, the
        S-flag / QRV bit split, the QQIC, and the full source-address
        list from a non-degenerate wire frame.

        Reference: RFC 3810 §5.1 (MLDv2 Query field layout).
        """

        message = Icmp6Mld2MessageQuery.from_buffer(_QUERY_FRAME)

        self.assertEqual(int(message.code), 0, msg="code must decode to 0.")
        self.assertEqual(message.cksum, 0x1234, msg="cksum must decode from bytes 2-3.")
        self.assertEqual(
            message.maximum_response_code,
            10000,
            msg="maximum_response_code must decode from bytes 4-5.",
        )
        self.assertEqual(
            message.multicast_address,
            Ip6Address("ff38::1234"),
            msg="multicast_address must decode from bytes 8-23.",
        )
        self.assertTrue(message.s_flag, msg="s_flag must decode from bit 3 of byte 24 (0x0a -> S set).")
        self.assertEqual(message.qrv, 2, msg="qrv must decode from bits 0-2 of byte 24 (0x0a -> 2).")
        self.assertEqual(message.qqic, 125, msg="qqic must decode from byte 25 (0x7d).")
        self.assertEqual(
            message.source_addresses,
            (Ip6Address("2001:db8::1"), Ip6Address("2001:db8::2")),
            msg="source_addresses must decode the 2 trailing 16-byte addresses.",
        )

    def test__icmp6__mld2__message__query__len_with_sources(self) -> None:
        """
        Ensure 'len()' equals the 28-byte fixed header plus 16 bytes per
        source address.

        Reference: RFC 3810 §5.1 (length = 28 + 16 × N sources).
        """

        message = Icmp6Mld2MessageQuery.from_buffer(_QUERY_FRAME)

        self.assertEqual(
            len(message),
            28 + 16 * 2,
            msg="MLDv2 Query length must be 28 + 16 × number-of-sources.",
        )

    def test__icmp6__mld2__message__query__str(self) -> None:
        """
        Ensure '__str__()' renders the decoded fields and the source
        count.

        Reference: RFC 3810 §5.1 (MLDv2 Query field layout).
        """

        message = Icmp6Mld2MessageQuery.from_buffer(_QUERY_FRAME)

        self.assertEqual(
            str(message),
            "ICMPv6 MLDv2 Query, mrc=10000, multicast=ff38::1234, qrv=2, qqic=125, sources=2",
            msg="Unexpected MLDv2 Query log string.",
        )

    def test__icmp6__mld2__message__query__from_buffer_wrong_type_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the type byte is
        MULTICAST_LISTENER_QUERY (130) and rejects any other.

        Reference: RFC 3810 §5.1 (MLDv2 Query type is 130).
        """

        with self.assertRaises(AssertionError):
            Icmp6Mld2MessageQuery.from_buffer(b"\x83" + _QUERY_FRAME[1:])

    def test__icmp6__mld2__message__query__integrity_dlen_under_min(self) -> None:
        """
        Ensure 'validate_integrity()' raises when the declared IPv6
        payload length is below the 28-byte fixed header.

        Reference: RFC 3810 §5.1 (Query header is at least 28 octets).
        """

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6Mld2MessageQuery.validate_integrity(frame=_QUERY_FRAME, ip6__dlen=27)

    def test__icmp6__mld2__message__query__integrity_source_list_truncated(self) -> None:
        """
        Ensure 'validate_integrity()' raises when the declared payload
        length does not cover the source-address list implied by the
        Number-of-Sources field.

        Reference: RFC 3810 §5.1 (payload must cover N × 16-byte sources).
        """

        # The frame declares 2 sources, so expected_len = 28 + 16 × 2 =
        # 60; ip6__dlen = 58 falls one source short of that boundary
        # (and lands between the 15× and 16× per-source computations, so
        # it also pins the source-stride multiplier).
        with self.assertRaises(Icmp6IntegrityError):
            Icmp6Mld2MessageQuery.validate_integrity(frame=_QUERY_FRAME, ip6__dlen=58)

    def test__icmp6__mld2__message__query__integrity_valid_frame_accepted(self) -> None:
        """
        Ensure 'validate_integrity()' accepts a well-formed frame whose
        payload length exactly covers the header plus source list.

        Reference: RFC 3810 §5.1 (well-formed Query is accepted).
        """

        Icmp6Mld2MessageQuery.validate_integrity(frame=_QUERY_FRAME, ip6__dlen=len(_QUERY_FRAME))

    def test__icmp6__mld2__message__query__integrity_exact_min_accepted(self) -> None:
        """
        Ensure 'validate_integrity()' accepts a 0-source Query whose
        payload length is exactly the 28-byte fixed header, pinning the
        inclusive lower bound against a '<' over-rejection.

        Reference: RFC 3810 §5.1 (a Query with no sources is 28 octets).
        """

        # 28-byte 0-source Query frame (Number of Sources = 0).
        frame = bytes.fromhex("8200000000000000" "ff380000000000000000000000001234" "00000000")
        Icmp6Mld2MessageQuery.validate_integrity(frame=frame, ip6__dlen=28)
