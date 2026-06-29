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
End-to-end proof points for the daemon-backed stdlib-socket drop-in.

Blocking TCP exchanges driven entirely through 'pytcp.socket' — the
stdlib-shaped 'socket()' factory, resolved against the daemon via the
'$PYTCP_DAEMON_SOCKET' singleton, with data exchanged over the wrapper's
'recv' / 'sendall' / 'makefile' / 'dup' / 'detach'. The capstone runs a
real stdlib 'http.client' GET round trip over a drop-in socket. Proves
the drop-in delegates correctly to the underlying client shim over the
live control RPC + SCM_RIGHTS data channel + bridge pump, using only
stdlib-shaped calls and constants.

pytcp/tests/integration/ipc/test__ipc__socket_dropin.py

ver 3.0.8
"""

import errno
import http.client
import io
import os
import select
import socket
import sys
import tempfile
import threading
import time
from types import ModuleType
from typing import override
from unittest.mock import create_autospec

import pytcp.socket as pytcp_socket
from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__enums import DnsRecordType
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.protocols.dns.dns__resolver import DnsResolver
from pytcp.socket.socket__dropin import Socket, _reset_default_stack
from pytcp.stack.resolver import ResolverApi
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpProbe, TcpTestCase

_RESOLVE_TABLE: dict[tuple[str, DnsRecordType], list[Ip4Address | Ip6Address]] = {
    ("echo.example", DnsRecordType.A): [HOST_A__IP4_ADDRESS],
}

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

        # Replace the daemon's resolver with a table-driven fake so the
        # hostname resolution paths resolve without a live upstream.
        resolver = create_autospec(DnsResolver, spec_set=True)
        resolver.resolve.side_effect = lambda host, record_type: _RESOLVE_TABLE.get((host, record_type), [])
        stack.resolver = ResolverApi(resolver=resolver)

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

    def test__socket_dropin__dup_shares_connection_and_is_independent(self) -> None:
        """
        Ensure dup() yields an independent descriptor on the same daemon
        connection: peer data is readable on the duplicate, and closing
        the duplicate leaves the original's data channel intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        self._drive_handshake(sock)

        duplicate = sock.dup()
        self.addCleanup(duplicate.close)
        duplicate.settimeout(_DEADLINE__SEC)

        self.assertNotEqual(
            duplicate.fileno(),
            sock.fileno(),
            msg="dup() must return a descriptor independent of the original.",
        )

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
                payload=b"alpha",
            )
        )
        self.assertEqual(
            duplicate.recv(64),
            b"alpha",
            msg="The duplicate must read peer data off the shared daemon connection.",
        )

        duplicate.close()
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS + 1 + len(b"alpha"),
                ack=_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"beta",
            )
        )
        self.assertEqual(
            sock.recv(64),
            b"beta",
            msg="Closing the duplicate must leave the original's data channel usable.",
        )

    def test__socket_dropin__dup_has_no_control_handle(self) -> None:
        """
        Ensure a duplicated socket carries no daemon control handle, so a
        control operation on it fails rather than acting on the
        connection.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        self._drive_handshake(sock)

        duplicate = sock.dup()
        self.addCleanup(duplicate.close)

        with self.assertRaises(OSError) as raised:
            duplicate.bind(("0.0.0.0", 18040))

        self.assertEqual(
            raised.exception.errno,
            errno.EOPNOTSUPP,
            msg="A control call on a duplicated socket must fail with EOPNOTSUPP.",
        )

    def test__socket_dropin__detach_yields_a_live_descriptor(self) -> None:
        """
        Ensure detach() returns the live data-channel descriptor and
        neutralizes the wrapper: peer data is readable on the salvaged
        descriptor and the wrapper reports a closed (-1) descriptor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        self._drive_handshake(sock)

        detached_fd = sock.detach()
        self.assertGreaterEqual(
            detached_fd,
            0,
            msg="detach() must return the live data-channel descriptor.",
        )
        self.assertEqual(
            sock.fileno(),
            -1,
            msg="A detached wrapper must report a closed (-1) descriptor.",
        )

        salvaged = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=detached_fd)
        self.addCleanup(salvaged.close)
        salvaged.settimeout(_DEADLINE__SEC)

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
                payload=b"gamma",
            )
        )
        self.assertEqual(
            salvaged.recv(64),
            b"gamma",
            msg="The descriptor returned by detach() must still receive peer data.",
        )

    def _wait_for_request(self, marker: bytes) -> int:
        """
        Block until the HTTP request has fully reached the wire (its
        in-order data bytes start with 'marker' and end the header block),
        nudging the virtual clock; return the total request length so the
        peer can acknowledge it.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        segments: dict[int, bytes] = {}
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == _LOCAL_PORT and probe.payload:
                    segments[probe.seq] = bytes(probe.payload)
            request = b"".join(segments[seq] for seq in sorted(segments))
            if request.startswith(marker) and b"\r\n\r\n" in request:
                return len(request)
            self._advance(ms=5)
            time.sleep(0.01)
        raise AssertionError("The HTTP request never reached the wire.")

    def test__socket_dropin__http_client_get_round_trip(self) -> None:
        """
        Ensure a real stdlib 'http.client.HTTPConnection' completes a GET
        request / response over a drop-in socket — exercising http.client's
        request serialization, 'sendall', and 'makefile'-based response
        parsing against the daemon-backed data channel.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        self._drive_handshake(sock)

        connection = http.client.HTTPConnection(str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)
        connection.sock = sock  # pre-connected drop-in socket
        self.addCleanup(connection.close)

        result: dict[str, object] = {}

        def run_get() -> None:
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                result["status"] = response.status
                result["body"] = response.read()
            except Exception as error:  # noqa: BLE001  # surface to the test thread
                result["error"] = error

        get_thread = threading.Thread(target=run_get, name="http-get")
        get_thread.start()
        self.addCleanup(get_thread.join)

        request_len = self._wait_for_request(b"GET / HTTP/1.1")

        http_response = b"HTTP/1.1 200 OK\r\n" b"Content-Length: 5\r\n" b"Connection: close\r\n" b"\r\n" b"hello"
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS + 1,
                ack=_ISS + 1 + request_len,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=http_response,
            )
        )

        get_thread.join(timeout=_DEADLINE__SEC)
        self.assertFalse(
            get_thread.is_alive(),
            msg="The http.client GET must complete once the 200 response is driven.",
        )
        self.assertNotIn(
            "error",
            result,
            msg=f"http.client GET raised over the drop-in socket: {result.get('error')!r}",
        )
        self.assertEqual(
            (result.get("status"), result.get("body")),
            (200, b"hello"),
            msg="http.client must parse the driven 200 response read over the drop-in socket.",
        )

    def test__socket_dropin__nonblocking_recv_and_select_readiness(self) -> None:
        """
        Ensure an established non-blocking drop-in socket raises
        BlockingIOError on an empty recv and becomes select-readable once
        peer data arrives — the asyncio readiness foundation on the real
        data-channel descriptor.

        Reference: RFC 9293 §3.10 (Segment arrives — data delivery).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        self._drive_handshake(sock)

        sock.setblocking(False)

        with self.assertRaises(BlockingIOError):
            sock.recv(64)
        self.assertEqual(
            select.select([sock], [], [], 0)[0],
            [],
            msg="An established socket with no inbound data must not be select-readable.",
        )

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
                payload=b"async",
            )
        )

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline and not select.select([sock], [], [], 0)[0]:
            self._advance(ms=10)
            time.sleep(0.01)

        self.assertEqual(
            select.select([sock], [], [], _DEADLINE__SEC)[0],
            [sock],
            msg="The socket must become select-readable once peer data arrives.",
        )
        self.assertEqual(
            sock.recv(64),
            b"async",
            msg="A non-blocking recv must return the peer data once readable.",
        )

    def test__socket_dropin__connect_ex_returns_zero_on_success(self) -> None:
        """
        Ensure connect_ex returns 0 once the handshake completes, mirroring
        stdlib connect_ex's error-number return.

        Reference: RFC 9293 §3.5 (Connection establishment).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        self._force_iss(_ISS)
        sock.bind(("0.0.0.0", _LOCAL_PORT))

        result: dict[str, object] = {}

        def run_connect_ex() -> None:
            result["rc"] = sock.connect_ex((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        connect_thread = threading.Thread(target=run_connect_ex, name="dropin-connect-ex")
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

        self.assertEqual(
            result.get("rc"),
            0,
            msg="connect_ex must return 0 once the handshake completes.",
        )

    def _wait_for_writable(self, sock: Socket) -> None:
        """
        Block until 'sock' becomes select-writable, nudging the virtual
        clock so the daemon connect worker can resolve the handshake and
        drain the priming filler.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            if select.select([], [sock], [], 0)[1]:
                return
            self._advance(ms=10)
            time.sleep(0.01)
        raise AssertionError("The non-blocking connect socket never became writable.")

    def test__socket_dropin__nonblocking_connect_einprogress_then_writable(self) -> None:
        """
        Ensure a non-blocking drop-in connect raises
        BlockingIOError(EINPROGRESS), keeps the socket not-writable
        until the SYN-ACK completes the handshake, then flips writable
        with SO_ERROR cleared to zero — all without the caller blocking
        the main thread on connect.

        Reference: RFC 9293 §3.5 (Connection establishment).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        self._force_iss(_ISS)
        sock.bind(("0.0.0.0", _LOCAL_PORT))
        sock.setblocking(False)

        with self.assertRaises(BlockingIOError) as ctx:
            sock.connect((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        self.assertEqual(
            ctx.exception.errno,
            errno.EINPROGRESS,
            msg="A non-blocking connect in progress must raise BlockingIOError(EINPROGRESS).",
        )

        self.assertEqual(
            select.select([], [sock], [], 0)[1],
            [],
            msg="The connecting socket must not be select-writable before the handshake completes.",
        )

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

        self._wait_for_writable(sock)
        self.assertEqual(
            select.select([], [sock], [], _DEADLINE__SEC)[1],
            [sock],
            msg="The socket must become select-writable once the handshake completes.",
        )
        self.assertEqual(
            sock.getsockopt(pytcp_socket.SOL_SOCKET, pytcp_socket.SO_ERROR),
            0,
            msg="SO_ERROR must read 0 once the non-blocking connect succeeds.",
        )

    def test__socket_dropin__nonblocking_connect_econnrefused_on_rst(self) -> None:
        """
        Ensure a non-blocking drop-in connect refused by a peer RST
        flips the socket writable and surfaces ECONNREFUSED through
        getsockopt(SO_ERROR) — the BSD failed-connect readiness edge.

        Reference: RFC 9293 §3.5 (Connection establishment).
        Reference: RFC 9293 §3.10.7.3 (RST handling in SYN-SENT).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        self._force_iss(_ISS)
        sock.bind(("0.0.0.0", _LOCAL_PORT))
        sock.setblocking(False)

        with self.assertRaises(BlockingIOError) as ctx:
            sock.connect((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        self.assertEqual(
            ctx.exception.errno,
            errno.EINPROGRESS,
            msg="A non-blocking connect in progress must raise BlockingIOError(EINPROGRESS).",
        )

        self._wait_for_local_syn()
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=0,
                ack=_ISS + 1,
                flags=("RST", "ACK"),
                win=0,
            )
        )

        self._wait_for_writable(sock)
        self.assertEqual(
            sock.getsockopt(pytcp_socket.SOL_SOCKET, pytcp_socket.SO_ERROR),
            errno.ECONNREFUSED,
            msg="SO_ERROR must read ECONNREFUSED after a non-blocking connect is refused by RST.",
        )

    def _wait_for_any_syn(self, *, dport: int) -> TcpProbe:
        """
        Block until a SYN (no ACK) is emitted to 'dport' from any local
        port, nudging the virtual clock; return the SYN's TX probe.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.dport == dport and "SYN" in probe.flags and "ACK" not in probe.flags:
                    return probe
            self._advance(ms=1)
            time.sleep(0.005)
        raise AssertionError(f"No SYN to port {dport} was emitted.")

    def test__socket_dropin__getaddrinfo_via_daemon_resolver(self) -> None:
        """
        Ensure 'pytcp.socket.getaddrinfo' resolves a host name through the
        daemon resolver, returning the stdlib-shaped 5-tuple.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self.assertEqual(
            pytcp_socket.getaddrinfo(
                "echo.example",
                _REMOTE_PORT,
                family=pytcp_socket.AF_INET,
                type=pytcp_socket.SOCK_STREAM,
            ),
            [(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM, 0, "", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))],
            msg="pytcp.socket.getaddrinfo must resolve through the daemon and return the 5-tuple.",
        )

    def test__socket_dropin__gethostbyname_via_daemon_resolver(self) -> None:
        """
        Ensure 'pytcp.socket.gethostbyname' resolves a host name to its
        IPv4 address string through the daemon resolver.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self.assertEqual(
            pytcp_socket.gethostbyname("echo.example"),
            str(HOST_A__IP4_ADDRESS),
            msg="pytcp.socket.gethostbyname must resolve a host name through the daemon.",
        )

    def test__socket_dropin__create_connection_by_hostname(self) -> None:
        """
        Ensure 'pytcp.socket.create_connection' resolves a host name via
        the daemon, opens a socket, completes the handshake, and exchanges
        data — the full stdlib connect path P1 bypassed.

        Reference: RFC 9293 §3.5 (Connection establishment).
        """

        self._force_iss(_ISS)

        result: dict[str, object] = {}

        def run_connect() -> None:
            try:
                result["sock"] = pytcp_socket.create_connection(("echo.example", _REMOTE_PORT))
            except Exception as error:  # surface to the test thread
                result["error"] = error

        connect_thread = threading.Thread(target=run_connect, name="dropin-create-conn")
        connect_thread.start()
        self.addCleanup(connect_thread.join)

        syn = self._wait_for_any_syn(dport=_REMOTE_PORT)
        local_port = syn.sport
        local_iss = syn.seq

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=local_port,
                seq=_PEER_ISS,
                ack=local_iss + 1,
                flags=("SYN", "ACK"),
                win=_PEER_WIN,
            )
        )
        connect_thread.join(timeout=_DEADLINE__SEC)

        self.assertNotIn(
            "error",
            result,
            msg=f"create_connection by hostname raised: {result.get('error')!r}",
        )
        sock = result["sock"]
        assert isinstance(sock, Socket)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=local_port,
                seq=_PEER_ISS + 1,
                ack=local_iss + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"resolved",
            )
        )

        self.assertEqual(
            sock.recv(64),
            b"resolved",
            msg="A socket from create_connection(hostname) must exchange data over the resolved connection.",
        )

    def _restore_sys_modules_socket(self, saved: ModuleType | None, /) -> None:
        """
        Restore (or remove) the real 'socket' entry in 'sys.modules' after
        a drop-in swap so the process-wide module table never leaks.
        """

        if saved is None:
            sys.modules.pop("socket", None)
        else:
            sys.modules["socket"] = saved

    def _wait_for_request_on(self, marker: bytes, /, *, local_port: int) -> int:
        """
        Block until the consumer's request bytes (in-order, starting with
        'marker') have reached the wire from 'local_port', nudging the
        virtual clock; return the total request length so the peer can
        acknowledge it.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        segments: dict[int, bytes] = {}
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == local_port and probe.payload:
                    segments[probe.seq] = bytes(probe.payload)
            request = b"".join(segments[seq] for seq in sorted(segments))
            if request.startswith(marker):
                return len(request)
            self._advance(ms=5)
            time.sleep(0.01)
        raise AssertionError("The consumer request never reached the wire.")

    def test__socket_dropin__sys_modules_swap_runs_unmodified_consumer(self) -> None:
        """
        Ensure swapping 'sys.modules["socket"]' for the drop-in lets an
        unmodified stdlib-socket consumer — one that does its own 'import
        socket' and 'socket.create_connection', with no PyTCP references —
        complete a TCP request/response over the daemon. This is the
        one-line drop-in claim proven end to end: a program written for
        the stdlib runs against the PyTCP stack unchanged.

        Reference: RFC 9293 §3.5 (Connection establishment).
        Reference: RFC 9293 §3.10 (Data exchange).
        """

        self._force_iss(_ISS)

        request = b"PING\r\n\r\n"
        reply = b"PONG\r\n"
        result: dict[str, object] = {}

        def unmodified_consumer(host: str, port: int, /) -> None:
            # Ordinary stdlib-socket client code — zero PyTCP imports. The
            # function-local 'import socket' resolves from sys.modules at
            # call time, so the swap below makes it bind the drop-in.
            import socket  # pylint: disable=import-outside-toplevel

            try:
                connection = socket.create_connection((host, port))
                try:
                    connection.sendall(request)
                    result["reply"] = connection.recv(64)
                finally:
                    connection.close()
            except Exception as error:  # surface to the test thread
                result["error"] = error

        saved_socket_module = sys.modules.get("socket")
        sys.modules["socket"] = pytcp_socket
        self.addCleanup(self._restore_sys_modules_socket, saved_socket_module)

        consumer_thread = threading.Thread(
            target=unmodified_consumer,
            args=("echo.example", _REMOTE_PORT),
            name="dropin-unmodified-consumer",
        )
        consumer_thread.start()
        self.addCleanup(consumer_thread.join)

        # Drive the handshake for the daemon-assigned (auto-bound) port.
        syn = self._wait_for_any_syn(dport=_REMOTE_PORT)
        local_port, local_iss = syn.sport, syn.seq
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=local_port,
                seq=_PEER_ISS,
                ack=local_iss + 1,
                flags=("SYN", "ACK"),
                win=_PEER_WIN,
            )
        )

        # Wait for the consumer's request, then drive the reply back.
        request_len = self._wait_for_request_on(request, local_port=local_port)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=local_port,
                seq=_PEER_ISS + 1,
                ack=local_iss + 1 + request_len,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=reply,
            )
        )

        consumer_thread.join(timeout=_DEADLINE__SEC)
        self.assertFalse(
            consumer_thread.is_alive(),
            msg="The unmodified consumer must complete once the reply is driven.",
        )
        self.assertNotIn(
            "error",
            result,
            msg=f"The unmodified consumer raised over the swapped socket module: {result.get('error')!r}",
        )
        self.assertEqual(
            result.get("reply"),
            reply,
            msg="The unmodified stdlib consumer must exchange data over the daemon via the sys.modules swap.",
        )
