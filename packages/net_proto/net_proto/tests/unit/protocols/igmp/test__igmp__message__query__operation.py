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
This module contains tests for the IGMP Membership Query parser.

net_proto/tests/unit/protocols/igmp/test__igmp__message__query__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto.protocols.igmp.message.igmp__message import IgmpVersion
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
    decode_igmp_float_code,
    encode_igmp_float_code,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IGMPv3 General Query (group 0.0.0.0, no sources).",
            # IGMPv3 Membership Query (12 bytes):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x64 -> Max Resp Code = 100 (10.0 s)
            #   Bytes 2-3 : 0x0000 -> checksum (placeholder)
            #   Bytes 4-7 : 0x00000000 -> Group Address 0.0.0.0 (General Query)
            #   Byte 8    : 0x02 -> Resv=0, S=0, QRV=2
            #   Byte 9    : 0x7d -> QQIC = 125 s
            #   Bytes 10-11: 0x0000 -> Number of Sources = 0
            "_frame": b"\x11\x64\x00\x00\x00\x00\x00\x00\x02\x7d\x00\x00",
            "_results": {
                "version": IgmpVersion.V3,
                "max_resp_code": 100,
                "max_response_time": 100,
                "group_address": Ip4Address("0.0.0.0"),
                "s_flag": False,
                "qrv": 2,
                "qqic": 125,
                "querier_query_interval": 125,
                "source_addresses": (),
                "number_of_sources": 0,
                "is_general_query": True,
                "__len__": 12,
            },
        },
        {
            "_description": "IGMPv3 Group-Specific Query (group 239.1.1.1, no sources).",
            # IGMPv3 Membership Query (12 bytes):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x64 -> Max Resp Code = 100
            #   Bytes 2-3 : 0x0000 -> checksum (placeholder)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            #   Byte 8    : 0x02 -> Resv=0, S=0, QRV=2
            #   Byte 9    : 0x00 -> QQIC = 0
            #   Bytes 10-11: 0x0000 -> Number of Sources = 0
            "_frame": b"\x11\x64\x00\x00\xef\x01\x01\x01\x02\x00\x00\x00",
            "_results": {
                "version": IgmpVersion.V3,
                "max_resp_code": 100,
                "max_response_time": 100,
                "group_address": Ip4Address("239.1.1.1"),
                "s_flag": False,
                "qrv": 2,
                "qqic": 0,
                "querier_query_interval": 0,
                "source_addresses": (),
                "number_of_sources": 0,
                "is_general_query": False,
                "__len__": 12,
            },
        },
        {
            "_description": "IGMPv3 Group-and-Source-Specific Query (2 sources, S flag set).",
            # IGMPv3 Membership Query (20 bytes):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0xff -> Max Resp Code = 0xff (float form -> 31744)
            #   Bytes 2-3 : 0x0000 -> checksum (placeholder)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            #   Byte 8    : 0x0a -> Resv=0, S=1, QRV=2
            #   Byte 9    : 0x00 -> QQIC = 0
            #   Bytes 10-11: 0x0002 -> Number of Sources = 2
            #   Bytes 12-15: 0xc0000201 -> Source 192.0.2.1
            #   Bytes 16-19: 0xc0000202 -> Source 192.0.2.2
            "_frame": (b"\x11\xff\x00\x00\xef\x01\x01\x01\x0a\x00\x00\x02\xc0\x00\x02\x01\xc0\x00\x02\x02"),
            "_results": {
                "version": IgmpVersion.V3,
                "max_resp_code": 0xFF,
                "max_response_time": 31744,
                "group_address": Ip4Address("239.1.1.1"),
                "s_flag": True,
                "qrv": 2,
                "qqic": 0,
                "querier_query_interval": 0,
                "source_addresses": (Ip4Address("192.0.2.1"), Ip4Address("192.0.2.2")),
                "number_of_sources": 2,
                "is_general_query": False,
                "__len__": 20,
            },
        },
        {
            "_description": "IGMPv2 General Query (8-byte form, Max Resp Time non-zero).",
            # IGMPv2 Membership Query (8 bytes):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x64 -> Max Resp Time = 100
            #   Bytes 2-3 : 0x0000 -> checksum (placeholder)
            #   Bytes 4-7 : 0x00000000 -> Group Address 0.0.0.0 (General Query)
            "_frame": b"\x11\x64\x00\x00\x00\x00\x00\x00",
            "_results": {
                "version": IgmpVersion.V2,
                "max_resp_code": 100,
                "max_response_time": 100,
                "group_address": Ip4Address("0.0.0.0"),
                "s_flag": False,
                "qrv": 0,
                "qqic": 0,
                "querier_query_interval": 0,
                "source_addresses": (),
                "number_of_sources": 0,
                "is_general_query": True,
                "__len__": 8,
            },
        },
        {
            "_description": "IGMPv1 General Query (8-byte form, Max Resp Time zero).",
            # IGMPv1 Membership Query (8 bytes):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x00 -> Max Resp Time = 0 (IGMPv1 discriminator)
            #   Bytes 2-3 : 0x0000 -> checksum (placeholder)
            #   Bytes 4-7 : 0x00000000 -> Group Address 0.0.0.0 (General Query)
            "_frame": b"\x11\x00\x00\x00\x00\x00\x00\x00",
            "_results": {
                "version": IgmpVersion.V1,
                "max_resp_code": 0,
                "max_response_time": 0,
                "group_address": Ip4Address("0.0.0.0"),
                "s_flag": False,
                "qrv": 0,
                "qqic": 0,
                "querier_query_interval": 0,
                "source_addresses": (),
                "number_of_sources": 0,
                "is_general_query": True,
                "__len__": 8,
            },
        },
    ]
)
class TestIgmpMessageQueryParser(TestCase):
    """
    The IGMP Membership Query parser ('from_buffer') tests.
    """

    _description: str
    _frame: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Parse the parametrized IGMP Query frame.
        """

        self._query = IgmpMessageQuery.from_buffer(self._frame)

    def test__igmp__query__version(self) -> None:
        """
        Ensure the parser classifies the Query version from its message
        length and Max Resp Code (8 octets + code 0 = v1, 8 octets +
        code != 0 = v2, 12+ octets = v3).

        Reference: RFC 3376 §7.1 (Query version discrimination).
        """

        self.assertIs(
            self._query.version,
            self._results["version"],
            msg=f"Unexpected version for case: {self._description}",
        )

    def test__igmp__query__fields(self) -> None:
        """
        Ensure the parser decodes the raw Query fields (Max Resp Code,
        Group Address, S flag, QRV, QQIC, source list).

        Reference: RFC 3376 §4.1 (Membership Query fields).
        Reference: RFC 2236 §2 (IGMPv2 Query fields).
        """

        for field_name in (
            "max_resp_code",
            "group_address",
            "s_flag",
            "qrv",
            "qqic",
            "source_addresses",
            "number_of_sources",
        ):
            with self.subTest(field=field_name):
                self.assertEqual(
                    getattr(self._query, field_name),
                    self._results[field_name],
                    msg=f"Unexpected {field_name!r} for case: {self._description}",
                )

    def test__igmp__query__derived_times(self) -> None:
        """
        Ensure the Max Resp Code and QQIC octets decode to their linear
        Max Resp Time / Querier's Query Interval values.

        Reference: RFC 3376 §4.1.1 (Max Resp Code decoding).
        Reference: RFC 3376 §4.1.7 (QQIC decoding).
        """

        self.assertEqual(
            self._query.max_response_time,
            self._results["max_response_time"],
            msg=f"Unexpected max_response_time for case: {self._description}",
        )
        self.assertEqual(
            self._query.querier_query_interval,
            self._results["querier_query_interval"],
            msg=f"Unexpected querier_query_interval for case: {self._description}",
        )

    def test__igmp__query__is_general_query(self) -> None:
        """
        Ensure a Query with group 0.0.0.0 and no sources reports as a
        General Query, and a group/source Query does not.

        Reference: RFC 3376 §4.1.11 (Query variants).
        """

        self.assertEqual(
            self._query.is_general_query,
            self._results["is_general_query"],
            msg=f"Unexpected is_general_query for case: {self._description}",
        )

    def test__igmp__query__len(self) -> None:
        """
        Ensure '__len__()' reports the on-wire message length (8 octets
        for v1/v2, 12 + 4N for v3).

        Reference: RFC 3376 §4.1 (Query message layout).
        """

        self.assertEqual(
            len(self._query),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )


class TestIgmpFloatCodeDecode(TestCase):
    """
    The IGMP Max Resp Code / QQIC floating-point decode tests.
    """

    def test__igmp__decode_float_code(self) -> None:
        """
        Ensure codes below 128 decode linearly and codes of 128 or more
        decode via the 1|exp|mant floating-point form
        (mant | 0x10) << (exp + 3).

        Reference: RFC 3376 §4.1.1 (Max Resp Code floating-point form).
        Reference: RFC 3376 §4.1.7 (QQIC floating-point form).
        """

        for code, expected in [
            (0, 0),  # Linear minimum.
            (100, 100),  # Linear.
            (127, 127),  # Linear maximum.
            (0x80, 128),  # exp=0, mant=0 -> 0x10 << 3.
            (0x8F, 248),  # exp=0, mant=0xf -> 0x1f << 3.
            (0xFF, 31744),  # exp=7, mant=0xf -> 0x1f << 10.
        ]:
            with self.subTest(code=code):
                self.assertEqual(
                    decode_igmp_float_code(code),
                    expected,
                    msg=f"decode_igmp_float_code({code:#04x}) must be {expected}.",
                )


class TestIgmpFloatCodeEncode(TestCase):
    """
    The IGMP Max Resp Code / QQIC floating-point encode tests.
    """

    def test__igmp__encode_float_code__linear(self) -> None:
        """
        Ensure a value below 128 encodes to itself (the linear form) and
        the boundary value 127 stays linear.

        Reference: RFC 3376 §4.1.1 (Max Resp Code linear form < 128).
        """

        for value in (0, 1, 100, 127):
            with self.subTest(value=value):
                self.assertEqual(
                    encode_igmp_float_code(value),
                    value,
                    msg=f"encode_igmp_float_code({value}) must be {value} (linear).",
                )

    def test__igmp__encode_float_code__representable_roundtrip(self) -> None:
        """
        Ensure every exactly-representable floating-point value round-trips
        through encode then decode unchanged.

        Reference: RFC 3376 §4.1.1 (Max Resp Code floating-point form).
        Reference: RFC 3376 §4.1.7 (QQIC floating-point form).
        """

        for value in (128, 248, 256, 8192, 31744):
            with self.subTest(value=value):
                self.assertEqual(
                    decode_igmp_float_code(encode_igmp_float_code(value)),
                    value,
                    msg=f"decode(encode({value})) must be {value} for a representable value.",
                )

    def test__igmp__encode_float_code__floor_and_saturate(self) -> None:
        """
        Ensure a non-representable value floors to the largest representable
        value at or below it, and a value beyond the maximum saturates at
        0xff (31744).

        Reference: RFC 3376 §4.1.1 (Max Resp Code floating-point form).
        """

        # 130 sits between 128 (0x80) and 136 (0x81); it floors to 128.
        self.assertEqual(
            encode_igmp_float_code(130),
            0x80,
            msg="encode_igmp_float_code(130) must floor to code 0x80 (decodes to 128).",
        )
        # Beyond the maximum representable value saturates at 0xff.
        self.assertEqual(
            encode_igmp_float_code(100_000),
            0xFF,
            msg="A value beyond the maximum representable must saturate at code 0xff.",
        )
