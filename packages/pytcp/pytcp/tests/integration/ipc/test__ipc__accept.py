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
End-to-end passive-open accept() integration test for the boundary.

An out-of-process client opens a TCP socket on the daemon, listens, and
accepts an inbound connection completed by a peer on the TAP wire — the
daemon spawns a fresh data channel for the accepted child and passes its
fd back via SCM_RIGHTS, so the client gets a real fd for the accepted
connection (Phase 4).

The client's accept() blocks on the daemon dispatch thread (in
'TcpSocket.accept'), so the test issues accept() on a background thread
and drives the passive handshake from the main thread; different threads,
so it completes without deadlock.

pytcp/tests/integration/ipc/test__ipc__accept.py

ver 3.0.8
"""

import os
import tempfile
import threading
from typing import cast, override

from pytcp import stack
from pytcp.client import ClientStack, ClientTcpSocket, connect
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket import AddressFamily, SocketType
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LISTEN_PORT: int = 80
_PEER_PORT: int = 50002
_LOCAL_ISS: int = 2000
_PEER_ISS: int = 7000
_PEER_WIN: int = 64240
_PEER_MSS: int = 1460
_DEADLINE__SEC: float = 5.0


class TestIpcAccept(TcpTestCase):
    """
    The out-of-process passive-open accept() integration test.
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
        Build the mocked TCP runtime (via 'TcpTestCase') then stand up an
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

    def _drive_passive_handshake(self) -> None:
        """
        Drive the inbound passive handshake on the wire: peer SYN, the
        timer-gated SYN-ACK, then the peer ACK that completes the
        connection and queues the child for accept.
        """

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_PEER_PORT,
                dport=_LISTEN_PORT,
                seq=_PEER_ISS,
                flags=("SYN",),
                win=_PEER_WIN,
                mss=_PEER_MSS,
            )
        )
        # The SYN-ACK is gated on the next timer tick (the SYN_RCVD
        # transmit branch), as in the active-open initial SYN.
        self._advance(ms=1)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_PEER_PORT,
                dport=_LISTEN_PORT,
                seq=_PEER_ISS + 1,
                ack=_LOCAL_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
            )
        )

    def test__accept__returns_child_with_peer_and_data(self) -> None:
        """
        Ensure a listening client socket accepts an inbound connection out
        of process: accept() returns a child socket carrying the peer
        address, and data the peer sends on the connection reaches the
        child over its real data-channel fd.

        Reference: RFC 9293 §3.5 (Passive OPEN / connection establishment).
        """

        listener = cast(ClientTcpSocket, self._connect().socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(listener.close)
        self._force_iss(_LOCAL_ISS)
        listener.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))
        listener.listen()

        accepted: list[tuple[ClientTcpSocket, tuple[str, int]]] = []

        def _accept() -> None:
            accepted.append(listener.accept())

        accept_thread = threading.Thread(target=_accept, name="accept")
        accept_thread.start()
        self.addCleanup(accept_thread.join)

        self._drive_passive_handshake()

        accept_thread.join(timeout=_DEADLINE__SEC)
        self.assertFalse(accept_thread.is_alive(), msg="accept() must return once the handshake completes.")

        child, peer = accepted[0]
        self.addCleanup(child.close)
        child.settimeout(_DEADLINE__SEC)

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_PEER_PORT,
                dport=_LISTEN_PORT,
                seq=_PEER_ISS + 1,
                ack=_LOCAL_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"hi",
            )
        )

        self.assertEqual(
            (peer, child.recv(64)),
            ((str(HOST_A__IP4_ADDRESS), _PEER_PORT), b"hi"),
            msg="accept() must return the peer address and a child whose fd receives the peer's data.",
        )
