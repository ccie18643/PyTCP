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
High-level asyncio streams proof: asyncio.start_server over the daemon.

Proves asyncio's transport + StreamReader/StreamWriter machinery works
over a daemon-backed drop-in socket passed via 'sock=' (the integration
path the async FTP server example uses — a global sys.modules['socket']
swap is NOT viable because asyncio's own event loop needs the real socket
module for its self-pipe / selector). An inbound connection on the
synthetic wire delivers a request line to the StreamReader and the
handler's StreamWriter response reaches the wire.

pytcp/tests/integration/ipc/test__ipc__asyncio_streams.py

ver 3.0.9
"""

import asyncio
import os
import socket
import tempfile
import threading
import time
from typing import cast, override

import pytcp.socket as pytcp_socket
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import _reset_default_stack
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LISTEN_PORT: int = 80
_PEER_PORT: int = 50002
_LOCAL_ISS: int = 2000
_PEER_ISS: int = 5000
_PEER_WIN: int = 64240
_PEER_MSS: int = 1460
_DEADLINE__SEC: float = 5.0


class TestIpcAsyncioStreams(TcpTestCase):
    """
    The high-level asyncio.start_server-over-daemon proof test.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging.
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
        the drop-in's daemon singleton at it.
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

    def _wait_for_data_tx(self, *, payload: bytes) -> None:
        """
        Block until the daemon emits a segment carrying 'payload'.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                if self._parse_tx(frame).payload == payload:
                    return
            self._advance(ms=1)
            time.sleep(0.005)
        raise AssertionError(f"Daemon did not emit a segment carrying {payload!r}.")

    def test__asyncio_streams__start_server_request_response(self) -> None:
        """
        Ensure asyncio.start_server's transport + StreamReader/Writer
        machinery works over a daemon-backed drop-in socket: an inbound
        connection delivers a request line to the handler and the handler's
        response reaches the wire.

        Reference: RFC 9293 §3.5 (Passive OPEN / connection establishment).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        listener = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        self._force_iss(_LOCAL_ISS)
        listener.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))

        got: dict[str, object] = {}

        async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            got["request"] = await reader.read(64)
            got["peer"] = writer.get_extra_info("peername")
            writer.write(b"220 pytcp-asyncio\r\n")
            await writer.drain()
            writer.close()

        async def _serve() -> None:
            server = await asyncio.start_server(_handle, sock=cast(socket.socket, listener))
            got["serving"] = True
            async with server:
                # Serve until the handler has captured the request.
                deadline = time.monotonic() + _DEADLINE__SEC
                while "request" not in got and time.monotonic() < deadline:
                    await asyncio.sleep(0.01)

        def _run() -> None:
            try:
                asyncio.run(_serve())
            except Exception as error:  # noqa: BLE001 - surfaced to the assertion
                import traceback

                got["error"] = error
                got["traceback"] = traceback.format_exc()

        thread = threading.Thread(target=_run, name="asyncio-streams", daemon=True)
        thread.start()
        self.addCleanup(thread.join, _DEADLINE__SEC)

        # Wait until asyncio.start_server has actually listened + armed its
        # accept reader before driving the wire (else the SYN races ahead of
        # the listener and is dropped).
        deadline = time.monotonic() + _DEADLINE__SEC
        while "serving" not in got and "error" not in got and time.monotonic() < deadline:
            time.sleep(0.01)

        # Wire peer: passive handshake, then a request line.
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
                payload=b"USER anonymous\r\n",
            )
        )

        self._wait_for_data_tx(payload=b"220 pytcp-asyncio\r\n")
        thread.join(timeout=_DEADLINE__SEC)

        self.assertNotIn("error", got, msg=f"asyncio.start_server raised: {got.get('error')!r}")
        self.assertEqual(
            got.get("request"),
            b"USER anonymous\r\n",
            msg="The asyncio StreamReader must receive the request line over the daemon.",
        )
