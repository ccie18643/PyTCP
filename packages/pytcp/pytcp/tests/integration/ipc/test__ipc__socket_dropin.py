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


"""
End-to-end proof point for the daemon-backed stdlib-socket drop-in.

A blocking TCP echo driven entirely through 'pytcp.socket' — the
stdlib-shaped 'socket()' factory, resolved against the daemon via the
'$PYTCP_DAEMON_SOCKET' singleton, with data exchanged over the wrapper's
'recv' / 'sendall'. Proves the drop-in delegates correctly to the
underlying client shim over the live control RPC + SCM_RIGHTS data
channel + bridge pump, using only stdlib-shaped calls and constants.

pytcp/tests/integration/ipc/test__ipc__socket_dropin.py

ver 3.0.8
"""

import io
import os
import tempfile
import threading
import time
from typing import override

import pytcp.socket as pytcp_socket
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import Socket, _reset_default_stack
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_PORT: int = 50001
_REMOTE_PORT: int = 80
_ISS: int = 1000
_PEER_ISS: int = 5000
_PEER_WIN: int = 64240
_DEADLINE__SEC: float = 5.0


class TestSocketDropinEcho(TcpTestCase):
    """
    The daemon-backed socket-drop-in end-to-end echo test.
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

        # Point the drop-in's process-wide daemon singleton at this test's
        # server, snapshotting / restoring the env and resetting the
        # singleton on both sides so the module-global state never leaks.
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

    def _wait_for_local_syn(self) -> None:
        """
        Block until the daemon has emitted the active-open SYN from the
        bound local port, nudging the virtual clock as it waits.
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

    def _drive_handshake(self, sock: Socket) -> None:
        """
        Drive 'sock' to ESTABLISHED: issue the blocking connect on a
        background thread, wait for the local SYN, inject the synthetic
        SYN-ACK, and join the connect thread.
        """

        self._force_iss(_ISS)
        sock.bind(("0.0.0.0", _LOCAL_PORT))

        connect_thread = threading.Thread(
            target=sock.connect,
            args=((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT),),
            name="dropin-connect",
        )
        connect_thread.start()
        self.addCleanup(connect_thread.join)

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
        connect_thread.join(timeout=_DEADLINE__SEC)
        self.assertFalse(
            connect_thread.is_alive(),
            msg="The drop-in connect() must return once the SYN-ACK is driven.",
        )

    def test__socket_dropin__factory_returns_wrapper_with_real_fileno(self) -> None:
        """
        Ensure 'pytcp.socket.socket()' returns the drop-in wrapper backed
        by a real, selectable data-channel descriptor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)

        self.assertIsInstance(
            sock,
            Socket,
            msg="pytcp.socket.socket() must return the daemon-backed Socket wrapper.",
        )
        self.assertGreaterEqual(
            sock.fileno(),
            0,
            msg="The drop-in socket must expose a real data-channel file descriptor.",
        )

    def test__socket_dropin__recv_delivers_peer_data(self) -> None:
        """
        Ensure data a peer sends on the wire is delivered to a drop-in
        socket via its stdlib-shaped 'recv'.

        Reference: RFC 9293 §3.10 (Segment arrives — data delivery to the
        user).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)

        self._drive_handshake(sock)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS + 1,
                ack=_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"ping",
            )
        )

        self.assertEqual(
            sock.recv(64),
            b"ping",
            msg="The drop-in recv() must return peer data over the real data-channel fd.",
        )

    def test__socket_dropin__sendall_reaches_the_wire(self) -> None:
        """
        Ensure data written through the drop-in's stdlib-shaped 'sendall'
        is carried by the stack onto the wire as a TCP data segment.

        Reference: RFC 9293 §3.10 (SEND call — user data to the network).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)

        self._drive_handshake(sock)
        sock.sendall(b"pong")

        deadline = time.monotonic() + _DEADLINE__SEC
        seen_payload = b""
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == _LOCAL_PORT and probe.payload:
                    seen_payload = probe.payload
                    break
            if seen_payload:
                break
            self._advance(ms=10)
            time.sleep(0.01)

        self.assertEqual(
            seen_payload,
            b"pong",
            msg="Data written via the drop-in sendall() must reach the wire as a TCP data segment.",
        )

    def test__socket_dropin__makefile_read_delivers_peer_line(self) -> None:
        """
        Ensure a buffered reader returned by makefile('rb') reads a line
        of peer data delivered over the drop-in's data channel — the path
        stdlib 'http.client' takes to read a response.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)

        self._drive_handshake(sock)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS + 1,
                ack=_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"HTTP/1.0 200 OK\r\n",
            )
        )

        reader = sock.makefile("rb")
        self.addCleanup(reader.close)
        assert isinstance(reader, io.BufferedReader)

        self.assertEqual(
            reader.readline(),
            b"HTTP/1.0 200 OK\r\n",
            msg="A makefile('rb') reader must read a line of peer data over the data channel.",
        )

    def test__socket_dropin__makefile_write_reaches_the_wire(self) -> None:
        """
        Ensure data written through a makefile('wb') buffered writer is
        carried by the stack onto the wire — the path stdlib 'http.client'
        takes to send a request.

        Reference: RFC 9293 §3.10 (SEND call — user data to the network).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)

        self._drive_handshake(sock)

        writer = sock.makefile("wb")
        self.addCleanup(writer.close)
        assert isinstance(writer, io.BufferedWriter)
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        writer.flush()

        deadline = time.monotonic() + _DEADLINE__SEC
        seen_payload = b""
        while time.monotonic() < deadline:
            seen_payload = b"".join(
                bytes(probe.payload)
                for probe in (self._parse_tx(frame) for frame in list(self._frames_tx))
                if probe.sport == _LOCAL_PORT and probe.payload
            )
            if seen_payload == b"GET / HTTP/1.0\r\n\r\n":
                break
            self._advance(ms=10)
            time.sleep(0.01)

        self.assertEqual(
            seen_payload,
            b"GET / HTTP/1.0\r\n\r\n",
            msg="Data written via a makefile('wb') writer must reach the wire as TCP data.",
        )
