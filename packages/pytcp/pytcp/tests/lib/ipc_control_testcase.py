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
This module contains the 'IpcControlTestCase' base — a 'NetworkTestCase'
extended with a live IPC server and client, for out-of-process
control-API integration tests.

'NetworkTestCase.setUp' installs the mocked runtime and the
'mock__init'-populated 'stack.<api>' control singletons over one
registered interface. This subclass adds an 'IpcServer' on a temp AF_UNIX
path and a '_connect()' helper returning a 'ClientStack', so a test can
drive the daemon's real control APIs from out of process and compare
against the in-process result.

pytcp/tests/lib/ipc_control_testcase.py

ver 3.0.10
"""

import os
import tempfile
from typing import override

from pytcp import stack
from pytcp.client import ClientStack, connect
from pytcp.ipc.ipc__server import IpcServer
from pytcp.tests.lib.network_testcase import NetworkTestCase


class IpcControlTestCase(NetworkTestCase):
    """
    Integration-test base for the out-of-process control-API mirrors.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging for the
        whole class. Emptying 'LOG__CHANNEL' here (before any per-test
        'NetworkTestCase.setUp' snapshots it) means the harness snapshots
        and restores the already-empty channel, so the server's
        cleanup-time 'Stopping IPC Server' line — emitted from an
        'addCleanup' that runs after 'NetworkTestCase.tearDown' restores
        its snapshot — stays silent.
        """

        super().setUpClass()
        cls._log_channel_prior = stack.LOG__CHANNEL
        stack.LOG__CHANNEL = set()

    @classmethod
    @override
    def tearDownClass(cls) -> None:
        """
        Restore the original logger channel set.
        """

        stack.LOG__CHANNEL = cls._log_channel_prior
        super().tearDownClass()

    @override
    def setUp(self) -> None:
        """
        Build the mocked runtime (via 'NetworkTestCase') then stand up an
        'IpcServer' on a temp AF_UNIX path against it.
        """

        super().setUp()

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)

        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def _connect(self) -> ClientStack:
        """
        Open a client stack against the server and register its close.
        """

        client = connect(socket_path=self._socket_path)
        self.addCleanup(client.close)
        return client

    @property
    def _ifindex(self) -> int:
        """
        Return the ifindex of the single registered fixture interface.
        """

        return stack.link.list_interfaces()[0]
