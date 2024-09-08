#!/usr/bin/env python3

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
This module contains tests for the TCP header fields asserts.

tests/unit/protocols/tcp/test__tcp__header__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from pytcp.lib.int_checks import (
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
)
from pytcp.protocols.tcp.tcp__header import TcpHeader


class TestTcpHeaderAsserts(TestCase):
    """
    The TCP header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP header constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "sport": 0,
            "dport": 0,
            "seq": 0,
            "ack": 0,
            "hlen": 0,
            "flag_ns": False,
            "flag_cwr": False,
            "flag_ece": False,
            "flag_urg": False,
            "flag_ack": False,
            "flag_psh": False,
            "flag_rst": False,
            "flag_syn": False,
            "flag_fin": False,
            "win": 0,
            "cksum": 0,
            "urg": 0,
        }

    def test__tcp__header__sport__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'sport' argument is lower than the minimum supported value.
        """

        self._kwargs["sport"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__header__sport__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'sport' argument is higher than the maximum supported value.
        """

        self._kwargs["sport"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__dport__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'dport' argument is lower than the minimum supported value.
        """

        self._kwargs["dport"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__dport__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'dport' argument is higher than the maximum supported value.
        """

        self._kwargs["dport"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__seq__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'seq' argument is lower than the minimum supported value.
        """

        self._kwargs["seq"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 32-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__seq__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'seq' argument is higher than the maximum supported value.
        """

        self._kwargs["seq"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 32-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__ack__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'ack' argument is lower than the minimum supported value.
        """

        self._kwargs["ack"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ack' field must be a 32-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__ack__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'ack' argument is higher than the maximum supported value.
        """

        self._kwargs["ack"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ack' field must be a 32-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__hlen__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'hlen' argument is lower than the minimum supported value.
        """

        self._kwargs["hlen"] = value = UINT_6__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hlen' field must be a 6-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__hlen__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'hlen' argument is higher than the maximum supported value.
        """

        self._kwargs["hlen"] = value = UINT_6__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hlen' field must be a 6-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__hlen__not_4_bytes_alligned(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception when
        the value of the provided 'hlen' argument is not 4 bytes aligned.
        """

        self._kwargs["hlen"] = value = UINT_6__MAX - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hlen' field must be 4-byte aligned. Got: {value!r}",
        )

    def test__tcp__assembler__flag_ns__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_ns' argument is not a boolean.
        """

        self._kwargs["flag_ns"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_ns' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_cwr__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_cwr' argument is not a boolean.
        """

        self._kwargs["flag_cwr"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_cwr' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_ece__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_ece' argument is not a boolean.
        """

        self._kwargs["flag_ece"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_ece' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_urg__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_urg' argument is not a boolean.
        """

        self._kwargs["flag_urg"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_urg' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_ack__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_ack' argument is not a boolean.
        """

        self._kwargs["flag_ack"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_ack' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_psh__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_psh' argument is not a boolean.
        """

        self._kwargs["flag_psh"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_psh' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_rst__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_rst' argument is not a boolean.
        """

        self._kwargs["flag_rst"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_rst' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_syn__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_syn' argument is not a boolean.
        """

        self._kwargs["flag_syn"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_syn' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__flag_fin__not_boolean(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the
        provided 'flag_fin' argument is not a boolean.
        """

        self._kwargs["flag_fin"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_fin' field must be a boolean. Got: {type(value)!r}",
        )

    def test__tcp__assembler__win__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'win' argument is lower than the minimum supported value.
        """

        self._kwargs["win"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'win' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__win__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'win' argument is higher than the maximum supported value.
        """

        self._kwargs["win"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'win' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__cksum__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'cksum' argument is lower than the minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__cksum__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'cksum' argument is higher than the maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__urg__under_min(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'urg' argument is lower than the minimum supported value.
        """

        self._kwargs["urg"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'urg' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__tcp__assembler__urg__over_max(self) -> None:
        """
        Ensure the TCP header constructor raises an exception when the provided
        'urg' argument is higher than the maximum supported value.
        """

        self._kwargs["urg"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'urg' field must be a 16-bit unsigned integer. Got: {value!r}",
        )
