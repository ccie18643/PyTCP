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
This module contains tests for the IPv6 header fields asserts.

net_proto/tests/unit/protocols/ip6/test__ip6__header__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address, IpVersion
from net_proto import (
    UINT_2__MAX,
    UINT_2__MIN,
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_20__MAX,
    UINT_20__MIN,
    Ip6Header,
    IpProto,
)


class TestIp6HeaderAsserts(TestCase):
    """
    The IPv6 header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the IPv6 header constructor
        so each test can override exactly one field and trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "dscp": 0,
            "ecn": 0,
            "flow": 0,
            "dlen": 0,
            "next": IpProto.RAW,
            "hop": 0,
            "src": Ip6Address(),
            "dst": Ip6Address(),
        }

    def test__ip6__header__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from masking future regressions that would
        make the baseline invalid. Also pins 'ver' to IpVersion.IP6
        because the field is set unconditionally via field(init=False).

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        header = Ip6Header(**self._kwargs)

        self.assertEqual(
            header.ver,
            IpVersion.IP6,
            msg="Default-constructed header must expose ver=IpVersion.IP6.",
        )

    def test__ip6__header__dscp__under_min(self) -> None:
        """
        Ensure the constructor rejects 'dscp' below UINT_6__MIN.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["dscp"] = value = UINT_6__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dscp' under UINT_6__MIN.",
        )

    def test__ip6__header__dscp__over_max(self) -> None:
        """
        Ensure the constructor rejects 'dscp' above UINT_6__MAX.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["dscp"] = value = UINT_6__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dscp' over UINT_6__MAX.",
        )

    def test__ip6__header__ecn__under_min(self) -> None:
        """
        Ensure the constructor rejects 'ecn' below UINT_2__MIN.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["ecn"] = value = UINT_2__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ecn' under UINT_2__MIN.",
        )

    def test__ip6__header__ecn__over_max(self) -> None:
        """
        Ensure the constructor rejects 'ecn' above UINT_2__MAX.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["ecn"] = value = UINT_2__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ecn' over UINT_2__MAX.",
        )

    def test__ip6__header__flow__under_min(self) -> None:
        """
        Ensure the constructor rejects 'flow' below UINT_20__MIN.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["flow"] = value = UINT_20__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flow' field must be a 20-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'flow' under UINT_20__MIN.",
        )

    def test__ip6__header__flow__over_max(self) -> None:
        """
        Ensure the constructor rejects 'flow' above UINT_20__MAX.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["flow"] = value = UINT_20__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flow' field must be a 20-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'flow' over UINT_20__MAX.",
        )

    def test__ip6__header__dlen__under_min(self) -> None:
        """
        Ensure the constructor rejects 'dlen' below UINT_16__MIN.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["dlen"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dlen' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dlen' under UINT_16__MIN.",
        )

    def test__ip6__header__dlen__over_max(self) -> None:
        """
        Ensure the constructor rejects 'dlen' above UINT_16__MAX.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["dlen"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dlen' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'dlen' over UINT_16__MAX.",
        )

    def test__ip6__header__next__not_IpProto(self) -> None:
        """
        Ensure the constructor rejects 'next' when it is not an IpProto.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["next"] = value = "not an IpProto"

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'next' field must be an IpProto. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-IpProto 'next'.",
        )

    def test__ip6__header__hop__under_min(self) -> None:
        """
        Ensure the constructor rejects 'hop' below UINT_8__MIN.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["hop"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hop' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'hop' under UINT_8__MIN.",
        )

    def test__ip6__header__hop__over_max(self) -> None:
        """
        Ensure the constructor rejects 'hop' above UINT_8__MAX.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["hop"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hop' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'hop' over UINT_8__MAX.",
        )

    def test__ip6__header__src__not_Ip6Address(self) -> None:
        """
        Ensure the constructor rejects 'src' when it is not an Ip6Address.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["src"] = value = "not an Ip6Address"

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be an Ip6Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip6Address 'src'.",
        )

    def test__ip6__header__dst__not_Ip6Address(self) -> None:
        """
        Ensure the constructor rejects 'dst' when it is not an Ip6Address.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        self._kwargs["dst"] = value = "not an Ip6Address"

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be an Ip6Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip6Address 'dst'.",
        )

    def test__ip6__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent IPv6
        header — exercises the bit-packed ver/dscp/ecn/flow word in
        bytes 0-3 plus every scalar wire field including the 128-bit
        src/dst addresses.

        Reference: RFC 8200 §3 (IPv6 header wire format).
        """

        original = Ip6Header(
            dscp=53,
            ecn=2,
            flow=0xABCDE,
            dlen=0x4321,
            next=IpProto.TCP,
            hop=64,
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
        )

        rebuilt = Ip6Header.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )
