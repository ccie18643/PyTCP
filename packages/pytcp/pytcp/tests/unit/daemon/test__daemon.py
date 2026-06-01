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
Tests for the PyTCP daemon socket-path default and CLI argument wiring.

pytcp/tests/unit/daemon/test__daemon.py

ver 3.0.8
"""

import os
import tempfile
from unittest import TestCase
from unittest.mock import ANY, patch

from pytcp.daemon.__main__ import build_parser, main
from pytcp.daemon.daemon import default_socket_path


class TestDaemonSocketPath(TestCase):
    """
    The daemon default-socket-path resolution tests.
    """

    def test__default_socket_path__uses_xdg_runtime_dir(self) -> None:
        """
        Ensure the default control-socket path is rooted at
        '$XDG_RUNTIME_DIR' when that runtime directory is set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}):
            self.assertEqual(
                default_socket_path(),
                "/run/user/1000/pytcp.sock",
                msg="The default socket path must live under $XDG_RUNTIME_DIR when it is set.",
            )

    def test__default_socket_path__falls_back_to_tempdir(self) -> None:
        """
        Ensure the default control-socket path falls back to the system
        temp directory when '$XDG_RUNTIME_DIR' is unset.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.dict(os.environ):
            os.environ.pop("XDG_RUNTIME_DIR", None)
            self.assertEqual(
                default_socket_path(),
                os.path.join(tempfile.gettempdir(), "pytcp.sock"),
                msg="The default socket path must fall back to the temp dir without $XDG_RUNTIME_DIR.",
            )


class TestDaemonCli(TestCase):
    """
    The daemon command-line argument-wiring tests.
    """

    def test__build_parser__defaults_and_flags(self) -> None:
        """
        Ensure the parser applies the documented defaults (interface
        'tap7', IPv4/IPv6 enabled) and honours the disable flags and
        typed address arguments.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        args = build_parser().parse_args(["--no-ip6", "--ip4-address", "10.0.1.7/24"])

        self.assertEqual(
            (args.interface, args.ip6_support, args.ip4_support, str(args.ip4_address)),
            ("tap7", False, True, "10.0.1.7/24"),
            msg="The daemon parser must apply defaults and honour --no-ip6 / --ip4-address.",
        )

    def test__main__threads_parsed_args_to_run_daemon(self) -> None:
        """
        Ensure 'main' threads the parsed command-line options through to
        'run_daemon' (with a readiness callback), so the CLI is a thin
        wrapper over the run loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.daemon.__main__.run_daemon", autospec=True) as run_daemon:
            main(["--ipc-socket", "/tmp/x.sock", "--interface", "tap9", "--no-ip4"])

        run_daemon.assert_called_once_with(
            socket_path="/tmp/x.sock",
            interface_name="tap9",
            mac_address=None,
            ip4_support=False,
            ip4_host=None,
            ip6_support=True,
            ip6_host=None,
            on_ready=ANY,
        )
