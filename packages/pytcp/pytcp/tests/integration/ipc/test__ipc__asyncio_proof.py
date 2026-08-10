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
asyncio proof point (P2): a real asyncio event loop over the daemon.

Drives the low-level asyncio socket primitives — loop.sock_connect /
sock_sendall / sock_recv / sock_accept — against daemon-backed drop-in
sockets, with the synthetic TCP wire as the peer. The asyncio selector
runs on a background thread polling the drop-in's real data-channel fd
(and, for a listener, its accept-readiness eventfd); the main thread
plays the peer on the wire. This exercises the non-blocking connect
(A3.3), non-blocking accept (A3.4), and data-phase readiness (A3.2)
through a genuine asyncio event loop, proving asyncio runs over the
daemon socket boundary.

pytcp/tests/integration/ipc/test__ipc__asyncio_proof.py

ver 3.0.10
"""

import asyncio
import os
import socket
import tempfile
import threading
import time
from collections.abc import Callable
from typing import cast, override

import pytcp.socket as pytcp_socket
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import Socket, _reset_default_stack
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LISTEN_PORT: int = 80
_LOCAL_PORT: int = 50001
_REMOTE_PORT: int = 80
_PEER_PORT: int = 50002
_ISS: int = 1000
_LOCAL_ISS: int = 2000
_PEER_ISS: int = 5000
_PEER_WIN: int = 64240
_PEER_MSS: int = 1460
_DEADLINE__SEC: float = 5.0


class TestIpcAsyncioProof(TcpTestCase):
    """
    The asyncio-over-daemon proof-point integration test.
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

    def _spawn(self, target: Callable[[], None], /, *, name: str) -> threading.Thread:
        """
        Start a daemon background thread running 'target' and register its
        join as a cleanup so a wedged coroutine cannot outlive the test.
        """

        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self.addCleanup(thread.join, _DEADLINE__SEC)
        return thread

    def _wait_for_local_syn(self) -> None:
        """
        Block until the daemon emits the active-open SYN from the bound
        local port, nudging the virtual clock as it waits.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == _LOCAL_PORT and "SYN" in probe.flags and "ACK" not in probe.flags:
                    return
            self._advance(ms=1)
            time.sleep(0.005)
        raise AssertionError("Daemon did not emit the active-open SYN.")

    def _wait_for_data_tx(self, *, sport: int, payload: bytes) -> None:
        """
        Block until the daemon emits a segment carrying 'payload' from
        'sport', nudging the virtual clock so the send buffer flushes.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == sport and probe.payload == payload:
                    return
            self._advance(ms=1)
            time.sleep(0.005)
        raise AssertionError(f"Daemon did not emit a segment carrying {payload!r}.")

    def test__asyncio__client_connect_send_recv_echo(self) -> None:
        """
        Ensure a real asyncio event loop drives a daemon-backed drop-in
        socket through sock_connect / sock_sendall / sock_recv and
        receives the peer's echo — proving the non-blocking connect and
        data-phase readiness work under asyncio over the daemon.

        Reference: RFC 9293 §3.5 (Connection establishment).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        self._force_iss(_ISS)
        sock.bind(("0.0.0.0", _LOCAL_PORT))
        sock.setblocking(False)

        result: dict[str, object] = {}

        async def _client() -> None:
            loop = asyncio.get_running_loop()
            # asyncio's loop.sock_* are duck-typed (they only call fileno /
            # connect / send / recv / getsockopt), so the drop-in Socket
            # works at runtime; its stubs over-specify 'socket.socket'.
            aio = cast(socket.socket, sock)
            await loop.sock_connect(aio, (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
            await loop.sock_sendall(aio, b"ping")
            result["data"] = await loop.sock_recv(aio, 64)

        def _run() -> None:
            try:
                asyncio.run(_client())
            except Exception as error:  # noqa: BLE001 - surfaced to the assertion
                result["error"] = error

        client_thread = self._spawn(_run, name="asyncio-client")

        # Wire peer: complete the active-open handshake, then echo the data.
        self._wait_for_local_syn()
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS,
                ack=_ISS + 1,
                flags=("SYN", "ACK"),
                win=_PEER_WIN,
            )
        )
        self._wait_for_data_tx(sport=_LOCAL_PORT, payload=b"ping")
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS + 1,
                ack=_ISS + 1 + len(b"ping"),
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"ping",
            )
        )

        client_thread.join(timeout=_DEADLINE__SEC)
        self.assertNotIn(
            "error",
            result,
            msg=f"The asyncio client coroutine raised: {result.get('error')!r}",
        )
        self.assertEqual(
            result.get("data"),
            b"ping",
            msg="asyncio sock_recv must return the peer's echo over the daemon socket.",
        )

    def test__asyncio__server_accept_recv_over_daemon(self) -> None:
        """
        Ensure a real asyncio event loop drives a daemon-backed listening
        drop-in socket through sock_accept and the accepted child through
        sock_recv — proving non-blocking accept works under asyncio over
        the daemon.

        Reference: RFC 9293 §3.5 (Passive OPEN / connection establishment).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        listener = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        self._force_iss(_LOCAL_ISS)
        listener.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))
        listener.listen()
        listener.setblocking(False)

        result: dict[str, object] = {}

        async def _server() -> None:
            loop = asyncio.get_running_loop()
            # See the client coroutine: the drop-in Socket is a duck-typed
            # stand-in for the 'socket.socket' asyncio's stubs require.
            aio = cast(socket.socket, listener)
            child, peer = await loop.sock_accept(aio)
            child.setblocking(False)
            result["child"] = child
            result["peer"] = peer
            result["data"] = await loop.sock_recv(child, 64)

        def _run() -> None:
            try:
                asyncio.run(_server())
            except Exception as error:  # noqa: BLE001 - surfaced to the assertion
                result["error"] = error

        server_thread = self._spawn(_run, name="asyncio-server")

        # Wire peer: drive the inbound passive handshake (the SYN-ACK is
        # timer-gated), then deliver application data to the child. The
        # child's bridge buffers RX in the session until accept lands, so
        # the data drive need not wait for the asyncio accept to complete.
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
                payload=b"pong",
            )
        )

        server_thread.join(timeout=_DEADLINE__SEC)
        if isinstance(child := result.get("child"), Socket):
            self.addCleanup(child.close)
        self.assertNotIn(
            "error",
            result,
            msg=f"The asyncio server coroutine raised: {result.get('error')!r}",
        )
        self.assertEqual(
            (result.get("peer"), result.get("data")),
            ((str(HOST_A__IP4_ADDRESS), _PEER_PORT), b"pong"),
            msg="asyncio sock_accept + sock_recv must yield the child peer address and its data.",
        )
