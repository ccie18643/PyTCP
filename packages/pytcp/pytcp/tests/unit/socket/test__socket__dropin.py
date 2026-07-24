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
This module contains surface tests for the daemon-backed socket drop-in.

pytcp/tests/unit/socket/test__socket__dropin.py

ver 3.0.8
"""

from unittest import TestCase

import pytcp.runtime.socket as runtime_socket
import pytcp.socket as pytcp_socket


class TestSocketDropinSurface(TestCase):
    """
    The 'pytcp.socket' drop-in constant / error / surface tests.
    """

    def test__socket__dropin__constants_mirror_runtime(self) -> None:
        """
        Ensure the drop-in re-exports the stdlib-shaped constants as the
        same objects the internal runtime socket module defines.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for name in ("AF_INET", "AF_INET6", "SOCK_STREAM", "SOCK_DGRAM", "SOL_SOCKET", "SO_REUSEADDR", "IPPROTO_TCP"):
            with self.subTest(name=name):
                self.assertIs(
                    getattr(pytcp_socket, name),
                    getattr(runtime_socket, name),
                    msg=f"pytcp.socket.{name} must be the same object as the runtime constant.",
                )

    def test__socket__dropin__error_aliases_are_stdlib_exceptions(self) -> None:
        """
        Ensure the drop-in's 'error' / 'timeout' aliases are the stdlib
        exception classes a real socket module exposes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            pytcp_socket.error,
            OSError,
            msg="pytcp.socket.error must be OSError, mirroring stdlib socket.",
        )
        self.assertIs(
            pytcp_socket.timeout,
            TimeoutError,
            msg="pytcp.socket.timeout must be TimeoutError, mirroring stdlib socket.",
        )

    def test__socket__dropin__socket_factory_is_callable(self) -> None:
        """
        Ensure the drop-in exposes a callable 'socket' factory and a
        'Socket' class, mirroring the stdlib socket module's surface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            callable(pytcp_socket.socket),
            msg="pytcp.socket.socket must be a callable factory.",
        )
        self.assertIsInstance(
            pytcp_socket.Socket,
            type,
            msg="pytcp.socket.Socket must be a class.",
        )

    def test__socket__dropin__pytcp_top_level_exposes_drop_in(self) -> None:
        """
        Ensure 'pytcp.socket' resolved from the top-level package is the
        daemon-backed drop-in (carrying the 'socket' factory), not the
        internal runtime module.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import pytcp

        self.assertIs(
            pytcp.socket,
            pytcp_socket,
            msg="pytcp.socket must resolve to the daemon-backed drop-in package.",
        )
        self.assertTrue(
            hasattr(pytcp.socket, "socket"),
            msg="The top-level pytcp.socket must expose the stdlib-shaped socket factory.",
        )
