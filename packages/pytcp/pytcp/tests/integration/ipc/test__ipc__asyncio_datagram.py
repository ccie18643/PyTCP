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
High-level asyncio datagram proof: loop.create_datagram_endpoint over the daemon.

Proves asyncio's datagram transport + DatagramProtocol machinery works over a
daemon-backed drop-in UDP socket passed via 'sock=' (the integration path an
async UDP service would use — a global sys.modules['socket'] swap is NOT viable
because asyncio's own event loop needs the real socket module for its self-pipe
/ selector). A datagram a peer sends on the synthetic wire is delivered to the
protocol's 'datagram_received', and the protocol's 'transport.sendto' reply
reaches the wire addressed to the peer.

pytcp/tests/integration/ipc/test__ipc__asyncio_datagram.py

ver 3.0.10
"""

import asyncio
import os
import socket
import tempfile
import threading
import time
from typing import Any, cast, override

import pytcp.socket as pytcp_socket
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import _reset_default_stack
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.udp_testcase import UdpTestCase

_LOCAL_PORT: int = 4444
_REMOTE_PORT: int = 5555
_DEADLINE__SEC: float = 5.0


class _EchoDatagramProtocol(asyncio.DatagramProtocol):
    """
    Capture the first inbound datagram + its sender and reply to it,
    recording state into a shared dict so the driving thread can assert.
    """

    def __init__(self, got: dict[str, Any]) -> None:
        """
        Initialize with the shared result dict.
        """

        self._got = got
        self._transport: asyncio.DatagramTransport | None = None

    @override
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Record the datagram transport for the reply.
        """

        self._transport = cast(asyncio.DatagramTransport, transport)

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        """
        Record the datagram + sender and reply with a 'pong:' echo.
        """

        self._got["data"] = data
        self._got["addr"] = addr
        assert self._transport is not None
        self._transport.sendto(b"pong:" + data, addr)


class TestIpcAsyncioDatagram(UdpTestCase):
    """
    The high-level asyncio.create_datagram_endpoint-over-daemon proof test.
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
        Build the mocked UDP runtime, stand up an 'IpcServer', and point
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

    def _peer_datagram(self, *, payload: bytes) -> bytes:
        """
        Build an Ethernet/IPv4/UDP datagram from the peer to the bound
        stack socket.
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__payload=UdpAssembler(
                        udp__sport=_REMOTE_PORT,
                        udp__dport=_LOCAL_PORT,
                        udp__payload=payload,
                    ),
                ),
            )
        )

    def _wait_for_data_tx(self, *, payload: bytes) -> None:
        """
        Block until the daemon emits a UDP datagram carrying 'payload' to
        the peer, then assert its destination port.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.payload == payload:
                    self.assertEqual(
                        (probe.dport, str(probe.ip_dst)),
                        (_REMOTE_PORT, str(HOST_A__IP4_ADDRESS)),
                        msg="The reply must be addressed to the peer's port and address.",
                    )
                    return
            time.sleep(0.01)
        raise AssertionError(f"Daemon did not emit a datagram carrying {payload!r}.")

    def test__asyncio_datagram__endpoint_receives_and_replies(self) -> None:
        """
        Ensure asyncio.create_datagram_endpoint's transport + DatagramProtocol
        machinery works over a daemon-backed drop-in UDP socket: a peer
        datagram on the wire is delivered to 'datagram_received' and the
        protocol's 'sendto' reply reaches the wire.

        Reference: RFC 768 (UDP — datagram delivery / source address).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind((str(STACK__IP4_HOST.address), _LOCAL_PORT))

        got: dict[str, Any] = {}

        async def _serve() -> None:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _EchoDatagramProtocol(got),
                sock=cast(socket.socket, sock),
            )
            got["serving"] = True
            try:
                # Stay open until the driving thread confirms the reply
                # reached the wire (the daemon TX pump is asynchronous, so
                # closing the socket the instant the inbound datagram
                # arrives would race the pump and drop the reply).
                deadline = time.monotonic() + _DEADLINE__SEC
                while not got.get("done") and time.monotonic() < deadline:
                    await asyncio.sleep(0.01)
            finally:
                transport.close()

        def _run() -> None:
            try:
                asyncio.run(_serve())
            except Exception as error:  # noqa: BLE001 - surfaced to the assertion
                import traceback

                got["error"] = error
                got["traceback"] = traceback.format_exc()

        thread = threading.Thread(target=_run, name="asyncio-datagram", daemon=True)
        thread.start()
        self.addCleanup(thread.join, _DEADLINE__SEC)

        # Wait until the datagram endpoint is armed before driving the wire.
        deadline = time.monotonic() + _DEADLINE__SEC
        while "serving" not in got and "error" not in got and time.monotonic() < deadline:
            time.sleep(0.01)

        self._drive_udp_rx(frame=self._peer_datagram(payload=b"ping"))

        self._wait_for_data_tx(payload=b"pong:ping")
        got["done"] = True
        thread.join(timeout=_DEADLINE__SEC)

        self.assertNotIn("error", got, msg=f"create_datagram_endpoint raised: {got.get('error')!r}")
        self.assertEqual(
            got.get("data"),
            b"ping",
            msg="The asyncio DatagramProtocol must receive the peer datagram over the daemon.",
        )
        self.assertEqual(
            got.get("addr"),
            (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT),
            msg="datagram_received must carry the peer's source address.",
        )
