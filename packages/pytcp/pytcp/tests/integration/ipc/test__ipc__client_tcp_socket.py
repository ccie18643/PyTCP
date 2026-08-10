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
Integration tests for the client-side TCP socket shim.

These exercise 'ClientStack.socket()' and the 'ClientTcpSocket' control
methods (the non-blocking ones — bind / getsockname / setsockopt /
getsockopt / close) over a live IPC server. The connect + data-transfer
path needs a driven TCP wire and lands in the echo test.

pytcp/tests/integration/ipc/test__ipc__client_tcp_socket.py

ver 3.0.10
"""

import errno
from typing import cast

from pytcp.client import ClientTcpSocket
from pytcp.runtime.socket import SO_KEEPALIVE, SOL_SOCKET, AddressFamily, SocketType
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcClientTcpSocket(IpcControlTestCase):
    """
    The client-side TCP socket shim integration tests.
    """

    def test__client_socket__open_has_real_fileno(self) -> None:
        """
        Ensure an opened client socket exposes a real, selectable file
        descriptor (its data-channel end), so it works with select /
        poll / epoll natively.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        sock = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)

        self.assertGreaterEqual(
            sock.fileno(),
            0,
            msg="A client socket must expose a real data-channel file descriptor.",
        )

    def test__client_socket__bind_then_getsockname(self) -> None:
        """
        Ensure a bind through the client shim is reflected by a
        subsequent getsockname over the same socket.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        client = self._connect()
        sock = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)

        sock.bind(("0.0.0.0", 18010))

        self.assertEqual(
            sock.getsockname(),
            ("0.0.0.0", 18010),
            msg="getsockname must reflect the address bound through the client shim.",
        )

    def test__client_socket__setsockopt_getsockopt_round_trip(self) -> None:
        """
        Ensure a setsockopt through the client shim is observable via a
        subsequent getsockopt over the same socket.

        Reference: RFC 1122 §4.2.3.6 (TCP keep-alive SO_KEEPALIVE).
        """

        client = self._connect()
        sock = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)

        sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

        self.assertEqual(
            sock.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            1,
            msg="getsockopt must read back the value set through the client shim.",
        )

    def test__client_socket__close_releases_daemon_handle(self) -> None:
        """
        Ensure closing the client socket releases the daemon handle, so a
        later call over the stale handle surfaces OSError(EBADF) — the
        same error the stdlib reports for a call on a closed descriptor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        sock = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))

        sock.close()

        with self.assertRaises(OSError) as raised:
            sock.getsockname()

        self.assertEqual(
            raised.exception.errno,
            errno.EBADF,
            msg="A call over a released daemon handle must surface OSError(EBADF), as for a closed fd.",
        )
