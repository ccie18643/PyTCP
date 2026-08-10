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
This module contains tests for the IPv6 Frag header fields asserts.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__header__asserts.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
    Ip6FragHeader,
    IpProto,
)


class TestIp6FragHeaderAsserts(TestCase):
    """
    The IPv6 Frag header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the IPv6 Frag header
        constructor so each test can override exactly one field and
        trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "next": IpProto.RAW,
            "offset": 0,
            "flag_mf": False,
            "id": 0,
        }

    def test__ip6_frag__header__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from masking future regressions that would
        make the baseline invalid.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        header = Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            header.next,
            IpProto.RAW,
            msg="Default-constructed header must expose next=IpProto.RAW.",
        )
        self.assertEqual(
            header.offset,
            0,
            msg="Default-constructed header must expose offset=0.",
        )
        self.assertFalse(
            header.flag_mf,
            msg="Default-constructed header must expose flag_mf=False.",
        )
        self.assertEqual(
            header.id,
            0,
            msg="Default-constructed header must expose id=0.",
        )

    def test__ip6_frag__header__next__not_IpProto(self) -> None:
        """
        Ensure the constructor rejects 'next' when it is not an IpProto.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["next"] = value = "not an IpProto"

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'next' field must be an IpProto. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-IpProto 'next'.",
        )

    def test__ip6_frag__header__offset__under_min(self) -> None:
        """
        Ensure the constructor rejects 'offset' below UINT_13__MIN.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["offset"] = value = UINT_13__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer (in 8-byte units). Got: {value!r}",
            msg="Unexpected assertion message for 'offset' under UINT_13__MIN.",
        )

    def test__ip6_frag__header__offset__over_max(self) -> None:
        """
        Ensure the constructor rejects 'offset' whose 8-byte-unit
        representation exceeds UINT_13__MAX. The field is stored in
        bytes, so the smallest rejected multiple-of-8 value is
        '(UINT_13__MAX + 1) << 3'.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["offset"] = value = (UINT_13__MAX + 1) << 3

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer (in 8-byte units). Got: {value!r}",
            msg="Unexpected assertion message for 'offset' over UINT_13__MAX.",
        )

    def test__ip6_frag__header__offset__not_8_byte_alligned(self) -> None:
        """
        Ensure the constructor rejects 'offset' values whose
        8-byte-unit representation fits in 13 bits but are not
        themselves 8-byte aligned. 'UINT_13__MAX - 1' is the largest
        such misaligned value, so the range check passes and the
        alignment assert that runs next fires.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["offset"] = value = UINT_13__MAX - 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be 8-byte aligned. Got: {value!r}",
            msg="Unexpected assertion message for non-8-byte-aligned 'offset'.",
        )

    def test__ip6_frag__header__flag_mf__not_boolean(self) -> None:
        """
        Ensure the constructor rejects 'flag_mf' when it is not a bool.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["flag_mf"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_mf' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_mf'.",
        )

    def test__ip6_frag__header__id__under_min(self) -> None:
        """
        Ensure the constructor rejects 'id' below UINT_32__MIN.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["id"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'id' under UINT_32__MIN.",
        )

    def test__ip6_frag__header__id__over_max(self) -> None:
        """
        Ensure the constructor rejects 'id' above UINT_32__MAX.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self._kwargs["id"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6FragHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'id' over UINT_32__MAX.",
        )

    def test__ip6_frag__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent IPv6
        Fragment header — exercises the 13-bit offset + reserved bits
        + 1-bit M flag bit-packed into bytes 2-3, plus the reserved
        byte 1 and the 32-bit identification.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        original = Ip6FragHeader(
            next=IpProto.TCP,
            offset=0x1F8,
            flag_mf=True,
            id=0xCAFEBABE,
        )

        rebuilt = Ip6FragHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )
