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
This module contains tests for the UDP header fields asserts.

net_proto/tests/unit/protocols/udp/test__udp__header__asserts.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import UDP__HEADER__LEN, UINT_16__MAX, UINT_16__MIN, UdpHeader


class TestUdpHeaderAsserts(TestCase):
    """
    The UDP header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the UDP header constructor
        so each test can override exactly one field and trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "sport": 0,
            "dport": 0,
            "plen": 0,
            "cksum": 0,
        }

    def test__udp__header__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from masking regressions that would make the
        baseline invalid.

        Reference: RFC 768 (UDP header wire format).
        """

        header = UdpHeader(**self._kwargs)

        self.assertEqual(
            len(header),
            UDP__HEADER__LEN,
            msg="Default-constructed header must serialize to the 8-byte UDP fixed header.",
        )

    def test__udp__header__sport__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'sport' argument is lower than the minimum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["sport"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sport' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'sport' under UINT_16__MIN.",
        )

    def test__udp__header__sport__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'sport' argument is higher than the maximum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["sport"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sport' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'sport' over UINT_16__MAX.",
        )

    def test__udp__header__dport__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'dport' argument is lower than the minimum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["dport"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dport' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dport' under UINT_16__MIN.",
        )

    def test__udp__header__dport__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'dport' argument is higher than the maximum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["dport"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dport' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dport' over UINT_16__MAX.",
        )

    def test__udp__header__plen__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'plen' argument is lower than the minimum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["plen"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'plen' under UINT_16__MIN.",
        )

    def test__udp__header__plen__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'plen' argument is higher than the maximum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["plen"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'plen' over UINT_16__MAX.",
        )

    def test__udp__header__cksum__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'cksum' argument is lower than the minimum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' under UINT_16__MIN.",
        )

    def test__udp__header__cksum__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the
        provided 'cksum' argument is higher than the maximum supported value.

        Reference: RFC 768 (UDP header wire format).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' over UINT_16__MAX.",
        )

    def test__udp__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent UDP
        header — locks in pack/unpack symmetry across every wire field.

        Reference: RFC 768 (UDP header wire format).
        """

        original = UdpHeader(sport=12345, dport=54321, plen=42, cksum=0)

        rebuilt = UdpHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )
