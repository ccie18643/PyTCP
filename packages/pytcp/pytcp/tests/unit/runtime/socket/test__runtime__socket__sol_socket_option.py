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
Tests for the 'SolSocketOption' SOL_SOCKET-level 'optname' enum
and its stdlib-parity bare aliases (SO_REUSEADDR / SO_ERROR / ...).

pytcp/tests/unit/runtime/socket/test__runtime__socket__sol_socket_option.py

ver 3.0.8
"""

from enum import IntEnum
from unittest import TestCase

from pytcp.runtime.socket import (
    SO_BINDTODEVICE,
    SO_BROADCAST,
    SO_ERROR,
    SO_LINGER,
    SO_OOBINLINE,
    SO_RCVBUF,
    SO_RCVTIMEO,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_SNDBUF,
    SO_SNDTIMEO,
    SolSocketOption,
)

# The Linux <sys/socket.h> / <asm-generic/socket.h> 'optname' values
# every SOL_SOCKET-level member carries, paired with its bare alias.
_LINUX_VALUES: dict[SolSocketOption, int] = {
    SolSocketOption.SO_REUSEADDR: 2,
    SolSocketOption.SO_ERROR: 4,
    SolSocketOption.SO_BROADCAST: 6,
    SolSocketOption.SO_SNDBUF: 7,
    SolSocketOption.SO_RCVBUF: 8,
    SolSocketOption.SO_OOBINLINE: 10,
    SolSocketOption.SO_LINGER: 13,
    SolSocketOption.SO_REUSEPORT: 15,
    SolSocketOption.SO_RCVTIMEO: 20,
    SolSocketOption.SO_SNDTIMEO: 21,
    SolSocketOption.SO_BINDTODEVICE: 25,
}

_BARE_ALIASES: dict[str, SolSocketOption] = {
    "SO_REUSEADDR": SO_REUSEADDR,
    "SO_ERROR": SO_ERROR,
    "SO_BROADCAST": SO_BROADCAST,
    "SO_SNDBUF": SO_SNDBUF,
    "SO_RCVBUF": SO_RCVBUF,
    "SO_OOBINLINE": SO_OOBINLINE,
    "SO_LINGER": SO_LINGER,
    "SO_REUSEPORT": SO_REUSEPORT,
    "SO_RCVTIMEO": SO_RCVTIMEO,
    "SO_SNDTIMEO": SO_SNDTIMEO,
    "SO_BINDTODEVICE": SO_BINDTODEVICE,
}


class TestSocketSolSocketOption(TestCase):
    """
    The 'SolSocketOption' SOL_SOCKET-level optname enum + bare-alias tests.
    """

    def test__socket__sol_socket_option__is_int_enum(self) -> None:
        """
        Ensure 'SolSocketOption' is an 'IntEnum' so its members are
        usable directly as the integer 'optname' argument to
        setsockopt / getsockopt.

        Reference: Linux <sys/socket.h> SOL_SOCKET optnames.
        """

        self.assertTrue(
            issubclass(SolSocketOption, IntEnum),
            msg="SolSocketOption must be an IntEnum (optname is an integer ABI value).",
        )

    def test__socket__sol_socket_option__members_carry_linux_values(self) -> None:
        """
        Ensure every 'SolSocketOption' member carries the Linux
        integer optname value a program written for the stdlib socket
        module keys off.

        Reference: Linux <sys/socket.h> / <asm-generic/socket.h> SO_* optnames.
        """

        for member, value in _LINUX_VALUES.items():
            with self.subTest(member=member.name):
                self.assertEqual(
                    int(member),
                    value,
                    msg=f"SolSocketOption.{member.name} must carry the Linux value {value}.",
                )

    def test__socket__sol_socket_option__so_error_carries_linux_value(self) -> None:
        """
        Ensure 'SO_ERROR' carries the Linux value 4 — the read-and-
        clear pending-error optname the non-blocking connect SO_ERROR
        edge reads to surface the asynchronous handshake result.

        Reference: Linux <asm-generic/socket.h> SO_ERROR=4.
        """

        self.assertEqual(
            int(SO_ERROR),
            4,
            msg="SO_ERROR must carry the Linux value 4.",
        )

    def test__socket__sol_socket_option__bare_aliases_are_enum_members(self) -> None:
        """
        Ensure the bare module-level 'SO_*' names are the
        'SolSocketOption' members themselves, not standalone ints —
        the stdlib-parity bare-alias pattern.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for name, alias in _BARE_ALIASES.items():
            with self.subTest(alias=name):
                self.assertIs(
                    alias,
                    SolSocketOption[name],
                    msg=f"The bare '{name}' must be the SolSocketOption.{name} member.",
                )

    def test__socket__sol_socket_option__aliases_are_int_compatible(self) -> None:
        """
        Ensure the bare aliases compare equal to their raw Linux
        integers so a program written for the stdlib socket module
        ('getsockopt(SOL_SOCKET, SO_ERROR)' or 'getsockopt(1, 4)')
        runs unchanged against PyTCP.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            SO_ERROR,
            4,
            msg="SO_ERROR must compare equal to the bare int 4.",
        )
        self.assertEqual(
            SO_REUSEADDR,
            2,
            msg="SO_REUSEADDR must compare equal to the bare int 2.",
        )
