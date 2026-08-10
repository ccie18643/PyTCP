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
Non-blocking accept() integration test for the daemon drop-in (A3.4).

A non-blocking listening drop-in socket is select-not-readable with an
empty accept queue and raises BlockingIOError(EAGAIN); once an inbound
passive handshake completes and queues a child, the listener fd (the
daemon's accept-readiness eventfd, passed at listen()) flips readable and
accept() returns the child without the caller blocking the main thread.

pytcp/tests/integration/ipc/test__ipc__nonblocking_accept.py

ver 3.0.9
"""

import errno
import os
import select
import tempfile
import time
from typing import override

import pytcp.socket as pytcp_socket
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import Socket, _reset_default_stack
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


class TestIpcNonblockingAccept(TcpTestCase):
    """
    The non-blocking accept() drop-in integration test.
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
        Build the mocked TCP runtime, stand up an 'IpcServer', and point
        the drop-in's daemon singleton at it via '$PYTCP_DAEMON_SOCKET'.
        """

        super().setUp()

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

        self._env_prior = os.environ.get("PYTCP_DAEMON_SOCKET")
        os.environ["PYTCP_DAEMON_SOCKET"] = self._socket_path
        _reset_default_stack()
        self.addCleanup(self._restore_env)
        self.addCleanup(_reset_default_stack)

    def _restore_env(self) -> None:
        """
        Restore the PYTCP_DAEMON_SOCKET environment variable.
        """

        if self._env_prior is None:
            os.environ.pop("PYTCP_DAEMON_SOCKET", None)
        else:
            os.environ["PYTCP_DAEMON_SOCKET"] = self._env_prior

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

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

    def _wait_for_readable(self, sock: Socket) -> None:
        """
        Block until 'sock' becomes select-readable, nudging the virtual
        clock so the queued child propagates to the accept-readiness fd.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            if select.select([sock], [], [], 0)[0]:
                return
            self._advance(ms=10)
            time.sleep(0.01)
        raise AssertionError("The non-blocking listener never became select-readable.")

    def test__nonblocking_accept__on_non_listening_socket_raises_einval(self) -> None:
        """
        Ensure accept() on a socket that was never placed into the LISTEN
        state (no listen() call) raises OSError(EINVAL) — matching stdlib
        — rather than blocking forever or returning a spurious child.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))
        # Non-blocking so a missing guard surfaces immediately (as the
        # wrong error) instead of hanging the test.
        sock.setblocking(False)

        with self.assertRaises(OSError) as ctx:
            sock.accept()

        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="accept() on a non-listening socket must raise OSError(EINVAL).",
        )

    def test__nonblocking_accept__eagain_then_readable_then_child(self) -> None:
        """
        Ensure a non-blocking listening drop-in socket is not
        select-readable and raises BlockingIOError(EAGAIN) with an empty
        accept queue, then becomes select-readable and returns the
        accepted child carrying the peer address once an inbound passive
        handshake completes — without the caller blocking on accept.

        Reference: RFC 9293 §3.5 (Passive OPEN / connection establishment).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        listener = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        self._force_iss(_LOCAL_ISS)
        listener.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))
        listener.listen()
        listener.setblocking(False)

        self.assertEqual(
            select.select([listener], [], [], 0)[0],
            [],
            msg="An empty-queue non-blocking listener must not be select-readable.",
        )
        with self.assertRaises(BlockingIOError) as ctx:
            listener.accept()
        self.assertEqual(
            ctx.exception.errno,
            errno.EAGAIN,
            msg="accept() on an empty non-blocking listener must raise BlockingIOError(EAGAIN).",
        )

        self._drive_passive_handshake()

        self._wait_for_readable(listener)
        self.assertEqual(
            select.select([listener], [], [], _DEADLINE__SEC)[0],
            [listener],
            msg="The listener must become select-readable once a child is queued.",
        )

        child, peer = listener.accept()
        self.addCleanup(child.close)
        self.assertEqual(
            peer,
            (str(HOST_A__IP4_ADDRESS), _PEER_PORT),
            msg="A non-blocking accept() must return the child carrying the peer address.",
        )

        self.assertEqual(
            select.select([listener], [], [], 0)[0],
            [],
            msg="The listener must return to not-readable once the only queued child is accepted.",
        )
