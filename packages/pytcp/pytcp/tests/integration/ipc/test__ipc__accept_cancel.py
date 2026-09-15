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

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for daemon-side cancellation of a blocking accept().

A client that disappears while its accept() is outstanding must not
strand the daemon's per-connection dispatch thread: the accept wait
notices the dropped client and unwinds, reaping the session's sockets,
rather than polling until the daemon itself stops.

pytcp/tests/integration/ipc/test__ipc__accept_cancel.py

ver 3.0.10
"""

import os
import tempfile
import threading
import time
from typing import cast, override

from pytcp import stack
from pytcp.client import ClientStack, ClientTcpSocket, connect
from pytcp.ipc.ipc__server import IpcServer
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.tests.lib.network_testcase import STACK__IP4_HOST
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LISTEN_PORT: int = 8080
# Generous next to the daemon's 0.2 s accept poll, but far below the
# "until the daemon stops" behaviour this pins against.
_CANCEL_DEADLINE__SEC: float = 5.0
_SETTLE__SEC: float = 0.5


class TestIpcAcceptCancel(TcpTestCase):
    """
    The daemon-side accept-cancellation tests.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging for the
        whole class so the server's cleanup-time stop line stays quiet.
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
        Build the mocked TCP runtime then stand up an 'IpcServer' on a
        temp AF_UNIX path against it.
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

    def _listening_client(self) -> tuple[ClientStack, ClientTcpSocket]:
        """
        Open a client stack with a listening TCP socket on the stack
        address, ready for a blocking accept().
        """

        client = connect(socket_path=self._socket_path)
        listener = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))
        listener.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))
        listener.listen()
        return client, listener

    def _daemon_threads(self) -> list[threading.Thread]:
        """
        Snapshot the daemon's per-connection dispatch threads.
        """

        with self._server._lock__clients:
            return list(self._server._client_threads)

    def test__accept__client_disconnect_releases_the_dispatch_thread(self) -> None:
        """
        Ensure dropping a client while its accept() is outstanding lets
        the daemon's dispatch thread for that connection unwind, instead
        of polling for an inbound connection until the daemon stops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client, listener = self._listening_client()

        accept_thread = threading.Thread(target=self._swallow_accept, args=(listener,), name="accept")
        accept_thread.daemon = True
        accept_thread.start()

        # Let the accept reach the daemon and settle into its wait.
        time.sleep(_SETTLE__SEC)
        dispatch_threads = self._daemon_threads()
        self.assertTrue(dispatch_threads, msg="The daemon must have a dispatch thread for the client.")

        client.close()

        deadline = time.monotonic() + _CANCEL_DEADLINE__SEC
        while time.monotonic() < deadline and any(thread.is_alive() for thread in dispatch_threads):
            time.sleep(0.05)

        self.assertFalse(
            any(thread.is_alive() for thread in dispatch_threads),
            msg=(
                "The daemon dispatch thread must unwind once the client "
                "issuing accept() disconnects, not poll until daemon stop."
            ),
        )

    def test__accept__session_sockets_are_reaped_on_disconnect(self) -> None:
        """
        Ensure the listening socket the cancelled accept() was serving is
        reaped when the client drops, so a stranded accept does not leak
        the session's handle table.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client, listener = self._listening_client()

        accept_thread = threading.Thread(target=self._swallow_accept, args=(listener,), name="accept")
        accept_thread.daemon = True
        accept_thread.start()

        time.sleep(_SETTLE__SEC)
        dispatch_threads = self._daemon_threads()

        client.close()

        deadline = time.monotonic() + _CANCEL_DEADLINE__SEC
        while time.monotonic() < deadline and any(thread.is_alive() for thread in dispatch_threads):
            time.sleep(0.05)

        self.assertEqual(
            len(stack.sockets),
            0,
            msg="The dropped client's listening socket must be reaped from the stack socket table.",
        )

    @staticmethod
    def _swallow_accept(listener: ClientTcpSocket, /) -> None:
        """
        Issue the blocking accept() that the test then cancels; the call
        is expected to fail once the connection carrying it is gone.
        """

        try:
            listener.accept()
        # The client end is torn down under this call by design — any
        # failure it surfaces is the cancellation, not a test error.
        except Exception:  # pylint: disable=broad-exception-caught
            pass
