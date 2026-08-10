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
Constructor-assertion unit tests for the SNAP (Sub-Network
Access Protocol) header dataclass.

net_proto/tests/unit/protocols/snap/test__snap__header__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    SNAP__HEADER__LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_24__MAX,
    UINT_24__MIN,
    SnapHeader,
)


class TestSnapHeaderAsserts(TestCase):
    """
    The SNAP header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the SNAP header
        constructor so each test can override one field and
        trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "oui": 0x000000,
            "pid": 0x0000,
        }

    def test__snap__header__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted —
        guards the negative tests from masking regressions
        that would make the minimum-valid SNAP header invalid.

        Reference: RFC 1042 §"Header Format" (5-byte SNAP header layout).
        """

        header = SnapHeader(**self._kwargs)

        self.assertEqual(
            len(header),
            SNAP__HEADER__LEN,
            msg="Default-constructed header must serialize to the 5-byte SNAP fixed header.",
        )

    def test__snap__header__oui__under_min(self) -> None:
        """
        Ensure the SNAP header constructor raises an
        AssertionError when 'oui' is below the 24-bit
        unsigned minimum.

        Reference: RFC 1042 §"Header Format" (OUI is a 24-bit field).
        """

        self._kwargs["oui"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            SnapHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'oui' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'oui' under UINT_24__MIN.",
        )

    def test__snap__header__oui__over_max(self) -> None:
        """
        Ensure the SNAP header constructor raises an
        AssertionError when 'oui' is above the 24-bit
        unsigned maximum.

        Reference: RFC 1042 §"Header Format" (OUI is a 24-bit field).
        """

        self._kwargs["oui"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            SnapHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'oui' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'oui' over UINT_24__MAX.",
        )

    def test__snap__header__pid__under_min(self) -> None:
        """
        Ensure the SNAP header constructor raises an
        AssertionError when 'pid' is below the 16-bit
        unsigned minimum.

        Reference: RFC 1042 §"Header Format" (Protocol ID is a 16-bit field).
        """

        self._kwargs["pid"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            SnapHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'pid' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'pid' under UINT_16__MIN.",
        )

    def test__snap__header__pid__over_max(self) -> None:
        """
        Ensure the SNAP header constructor raises an
        AssertionError when 'pid' is above the 16-bit
        unsigned maximum.

        Reference: RFC 1042 §"Header Format" (Protocol ID is a 16-bit field).
        """

        self._kwargs["pid"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            SnapHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'pid' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'pid' over UINT_16__MAX.",
        )

    def test__snap__header__oui__boundary_max_accepted(self) -> None:
        """
        Ensure the SNAP header constructor accepts 'oui' =
        UINT_24__MAX (the inclusive 24-bit upper bound).
        Guards against a future tightening that would
        silently reject the maximum-valid OUI.

        Reference: RFC 1042 §"Header Format" (OUI is a 24-bit field).
        """

        self._kwargs["oui"] = UINT_24__MAX

        header = SnapHeader(**self._kwargs)

        self.assertEqual(
            header.oui,
            UINT_24__MAX,
            msg="UINT_24__MAX must be an accepted 'oui' value.",
        )

    def test__snap__header__pid__boundary_max_accepted(self) -> None:
        """
        Ensure the SNAP header constructor accepts 'pid' =
        UINT_16__MAX (the inclusive 16-bit upper bound).

        Reference: RFC 1042 §"Header Format" (Protocol ID is a 16-bit field).
        """

        self._kwargs["pid"] = UINT_16__MAX

        header = SnapHeader(**self._kwargs)

        self.assertEqual(
            header.pid,
            UINT_16__MAX,
            msg="UINT_16__MAX must be an accepted 'pid' value.",
        )

    def test__snap__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent SNAP
        header — locks in pack/unpack symmetry across the 3-byte OUI
        and the 16-bit Protocol ID.

        Reference: RFC 1042 §"Header Format" (5-byte SNAP header layout).
        """

        self._kwargs["oui"] = 0x00000C
        self._kwargs["pid"] = 0x0800

        original = SnapHeader(**self._kwargs)

        rebuilt = SnapHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )
