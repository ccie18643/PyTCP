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
Integration tests for the IPC AF_UNIX server + client PING round-trip.

pytcp/tests/integration/ipc/test__ipc__server__ping.py

ver 3.0.9
"""

import os
import tempfile
import threading
from typing import override
from unittest import TestCase

from pytcp import stack
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__server import IpcServer

_LOG__CHANNEL_PRIOR: set[str] = set()


def setUpModule() -> None:
    """
    Silence the 'stack'-channel Subsystem lifecycle logging for the
    duration of this module so the IPC server's Initializing / Starting
    / Stopping lines do not speckle the test progress output.
    """

    global _LOG__CHANNEL_PRIOR
    _LOG__CHANNEL_PRIOR = stack.LOG__CHANNEL
    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the original logger channel set.
    """

    stack.LOG__CHANNEL = _LOG__CHANNEL_PRIOR


class TestIpcServerPing(TestCase):
    """
    The IPC AF_UNIX server + client PING round-trip tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up an 'IpcServer' on a temp AF_UNIX path and register its
        teardown before opening any client.
        """

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)

        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any AF_UNIX socket node left in
        it (runs last in LIFO cleanup order, after the server stops).
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def _connect(self) -> IpcClient:
        """
        Open a client against the server and register its close.
        """

        client = IpcClient(socket_path=self._socket_path)
        self.addCleanup(client.close)
        return client

    def test__ipc__server__ping_returns_pong(self) -> None:
        """
        Ensure a client PING over the AF_UNIX control channel elicits
        a 'PONG' reply from the daemon, proving the end-to-end frame +
        envelope + transport path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            client.ping(),
            b"PONG",
            msg="A PING request must elicit a b'PONG' reply body.",
        )

    def test__ipc__server__ping_response_envelope(self) -> None:
        """
        Ensure the PING response is a success-kind message carrying the
        same op and the request's correlation id, so the client can
        match a reply to its request.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        response = client.request(IpcOp.PING)

        self.assertEqual(
            (response.kind, response.op),
            (IpcMessageKind.RESPONSE_OK, IpcOp.PING),
            msg="A PING reply must be RESPONSE_OK with op PING.",
        )

    def test__ipc__server__correlation_id_echoed(self) -> None:
        """
        Ensure the server echoes the request's correlation id back in
        the response, and the client increments it per request, so
        replies are matchable across multiple in-flight requests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        first = client.request(IpcOp.PING)
        second = client.request(IpcOp.PING)

        self.assertEqual(
            (second.req_id, second.req_id - first.req_id),
            (first.req_id + 1, 1),
            msg="The client must increment req_id per request and the server echo it.",
        )

    def test__ipc__server__sequential_pings(self) -> None:
        """
        Ensure many sequential requests on one connection all succeed,
        proving the per-client dispatch loop keeps serving after the
        first reply.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        self.assertEqual(
            [client.ping() for _ in range(50)],
            [b"PONG"] * 50,
            msg="Every sequential PING on one connection must return b'PONG'.",
        )

    def test__ipc__server__concurrent_clients(self) -> None:
        """
        Ensure multiple client connections are served simultaneously,
        proving the server spawns an independent dispatch loop per
        accepted connection.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        clients = [self._connect() for _ in range(4)]
        results: list[bytes] = []
        results_lock = threading.Lock()

        def _ping_worker(client: IpcClient) -> None:
            reply = client.ping()
            with results_lock:
                results.append(reply)

        workers = [threading.Thread(target=_ping_worker, args=(client,)) for client in clients]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5.0)

        self.assertEqual(
            results,
            [b"PONG"] * 4,
            msg="Each concurrently-connected client must receive its own b'PONG'.",
        )

    def test__ipc__server__unknown_op_returns_error(self) -> None:
        """
        Ensure a request the server has no handler for elicits a
        RESPONSE_ERROR rather than a dropped connection, so a client
        learns the op is unsupported.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()

        # IpcOp has only PING (0) today; 0xFFFF is a not-yet-defined op
        # the client sends directly (op is a raw int vocabulary) to
        # exercise the unsupported-op error path.
        response = client.request(0xFFFF)

        self.assertEqual(
            response.kind,
            IpcMessageKind.RESPONSE_ERROR,
            msg="An unsupported op must elicit a RESPONSE_ERROR reply.",
        )
