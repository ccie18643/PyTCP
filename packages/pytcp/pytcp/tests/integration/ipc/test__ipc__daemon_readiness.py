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
Tests for the 'wait_for_daemon' client readiness helper.

The helper only needs the daemon's control socket to be accepting, so a
bare 'IpcServer' (no stack) is sufficient to exercise it.

pytcp/tests/integration/ipc/test__ipc__daemon_readiness.py

ver 3.0.9
"""

import os
import tempfile
from typing import override
from unittest import TestCase

from pytcp import stack
from pytcp.client import wait_for_daemon
from pytcp.ipc.ipc__errors import IpcConnectionError
from pytcp.ipc.ipc__server import IpcServer


class TestIpcDaemonReadiness(TestCase):
    """
    The daemon-readiness ('wait_for_daemon') tests.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the stack log channel and prepare a temp directory for the
        control socket.
        """

        self._log_prior = stack.LOG__CHANNEL
        stack.LOG__CHANNEL = set()
        self.addCleanup(self._restore_log_channel)

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")

    def _restore_log_channel(self) -> None:
        """
        Restore the original stack log channel.
        """

        stack.LOG__CHANNEL = self._log_prior

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def test__wait_for_daemon__returns_once_the_socket_is_listening(self) -> None:
        """
        Ensure 'wait_for_daemon' returns once the daemon's control socket
        is accepting connections.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        server = IpcServer(socket_path=self._socket_path)
        server.start()
        self.addCleanup(server.stop)

        # Returns without raising (no assertion form needed; a timeout
        # would raise and fail the test).
        wait_for_daemon(socket_path=self._socket_path, timeout=5.0)

    def test__wait_for_daemon__times_out_when_no_daemon(self) -> None:
        """
        Ensure 'wait_for_daemon' raises 'IpcConnectionError' when no
        daemon is listening within the timeout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcConnectionError):
            wait_for_daemon(socket_path=os.path.join(self._tmp_dir, "absent.sock"), timeout=0.2)
