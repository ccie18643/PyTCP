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
Integration tests for the 'pytcp' CLI multitool.

These run the CLI's 'main' against the live IPC server (pointed at the
harness daemon via '--ipc-socket'), capturing stdout, to verify the
dispatch + connect + render path end to end for the observation
subcommands.

pytcp/tests/integration/ipc/test__ipc__cli.py

ver 3.0.8
"""

import contextlib
import io
from typing import cast

from pytcp.cli.__main__ import main
from pytcp.cli.cli__format import format_route_table
from pytcp.client import ClientTcpSocket
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcCli(IpcControlTestCase):
    """
    The 'pytcp' CLI multitool integration tests.
    """

    def _run(self, *argv: str) -> str:
        """
        Run the CLI with the given args against the harness server,
        returning the captured stdout.
        """

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main([*argv, "--ipc-socket", self._socket_path])
        self.assertEqual(exit_code, 0, msg="The CLI command must exit successfully.")
        return buffer.getvalue()

    def test__cli__ss_lists_listening_socket(self) -> None:
        """
        Ensure 'pytcp ss -t -l' renders a listening TCP socket opened on
        the daemon.

        Reference: RFC 9293 §3.3.2 (LISTEN state).
        """

        sock = cast(ClientTcpSocket, self._connect().socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)
        sock.bind(("0.0.0.0", 40010))
        sock.listen(backlog=8)

        output = self._run("ss", "-t", "-l")

        self.assertIn(
            "tcp",
            output,
            msg="The ss output must include the TCP netid for a listening socket.",
        )
        self.assertIn(
            "0.0.0.0:40010",
            output,
            msg="The ss output must include the listening socket's local endpoint.",
        )

    def test__cli__route_matches_formatter(self) -> None:
        """
        Ensure 'pytcp route' renders the daemon's routing table identically
        to the route formatter applied to the live route list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = format_route_table(self._connect().route.list_routes())

        output = self._run("route")

        self.assertEqual(
            output.rstrip("\n"),
            expected,
            msg="The route output must match the formatter over the live route list.",
        )

    def test__cli__sysctl_lists_entries(self) -> None:
        """
        Ensure 'pytcp sysctl' with no key lists the tunables as 'key =
        value' lines.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("sysctl")

        self.assertIn(
            " = ",
            output,
            msg="The sysctl listing must render 'key = value' lines.",
        )
