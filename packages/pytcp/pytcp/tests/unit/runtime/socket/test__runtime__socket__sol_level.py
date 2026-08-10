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
Tests for the 'SolLevel' setsockopt-'level' enum and its
stdlib-parity bare aliases ('SOL_SOCKET' / 'SOL_UDP').

pytcp/tests/unit/runtime/socket/test__runtime__socket__sol_level.py

ver 3.0.10
"""

from enum import IntEnum
from unittest import TestCase

from pytcp.runtime.socket import SOL_SOCKET, SOL_UDP, SolLevel


class TestSocketSolLevel(TestCase):
    """
    The 'SolLevel' setsockopt-level enum + bare-alias tests.
    """

    def test__socket__sol_level__is_int_enum(self) -> None:
        """
        Ensure 'SolLevel' is an 'IntEnum' so its members are usable
        directly as the integer 'level' argument to setsockopt /
        getsockopt.

        Reference: Linux <sys/socket.h> SOL_SOCKET / <netinet/udp.h> SOL_UDP.
        """

        self.assertTrue(
            issubclass(SolLevel, IntEnum),
            msg="SolLevel must be an IntEnum (level is an integer ABI value).",
        )

    def test__socket__sol_level__members_carry_linux_values(self) -> None:
        """
        Ensure the 'SolLevel' members carry the Linux integer values
        diagnostic and option-setting code keys off.

        Reference: Linux <sys/socket.h> SOL_SOCKET=1 / <netinet/udp.h> SOL_UDP=17.
        """

        self.assertEqual(
            SolLevel.SOL_SOCKET,
            1,
            msg="SolLevel.SOL_SOCKET must carry the Linux value 1.",
        )
        self.assertEqual(
            SolLevel.SOL_UDP,
            17,
            msg="SolLevel.SOL_UDP must carry the Linux value 17 (= IPPROTO_UDP).",
        )

    def test__socket__sol_level__bare_aliases_are_enum_members(self) -> None:
        """
        Ensure the bare module-level 'SOL_SOCKET' / 'SOL_UDP' names
        are the 'SolLevel' members themselves, not standalone ints —
        the stdlib-parity bare-alias pattern.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            SOL_SOCKET,
            SolLevel.SOL_SOCKET,
            msg="The bare 'SOL_SOCKET' must be the SolLevel.SOL_SOCKET member.",
        )
        self.assertIs(
            SOL_UDP,
            SolLevel.SOL_UDP,
            msg="The bare 'SOL_UDP' must be the SolLevel.SOL_UDP member.",
        )

    def test__socket__sol_level__aliases_are_int_compatible(self) -> None:
        """
        Ensure the bare aliases compare equal to their raw Linux
        integers so a program written for the stdlib socket module
        ('setsockopt(1, ...)' or 'setsockopt(SOL_SOCKET, ...)') runs
        unchanged against PyTCP.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(SOL_SOCKET),
            1,
            msg="int(SOL_SOCKET) must equal the Linux value 1.",
        )
        self.assertEqual(
            SOL_SOCKET,
            1,
            msg="SOL_SOCKET must compare equal to the bare int 1.",
        )
        self.assertEqual(
            SOL_UDP,
            17,
            msg="SOL_UDP must compare equal to the bare int 17.",
        )
