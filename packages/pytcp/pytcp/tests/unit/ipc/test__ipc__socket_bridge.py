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
Tests for the daemon-side per-socket data bridge.

The stack socket the bridge drives is stood in for by a socketpair end
wrapped in '_StackSocketStub', which adapts a plain socket to the
'recv(bufsize, timeout)' / 'send' / 'shutdown' surface the bridge calls.

pytcp/tests/unit/ipc/test__ipc__socket_bridge.py

ver 3.0.8
"""

import socket
import time
from typing import override
from unittest import TestCase

from pytcp.ipc.ipc__socket_bridge import SocketBridge


class _StackSocketStub:
    """
    Adapt a plain socket to the bridge's stack-socket surface.
    """

    def __init__(self, sock: socket.socket, /) -> None:
        self._sock = sock

    def recv(self, bufsize: int, timeout: float) -> bytes:
        self._sock.settimeout(timeout)
        return self._sock.recv(bufsize)

    def send(self, data: bytes) -> int:
        return self._sock.send(data)

    def shutdown(self, how: int, /) -> None:
        self._sock.shutdown(how)


class TestIpcSocketBridge(TestCase):
    """
    The daemon-side per-socket data-bridge tests.
    """

    @override
    def setUp(self) -> None:
        """
        Wire a bridge between a 'stack' socketpair (inner end wrapped in
        the stub, peer end is the simulated remote) and a 'data'
        socketpair (daemon end driven by the bridge, client end is the
        simulated client fd).
        """

        self._stack_inner, self._stack_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._data_end, self._client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        for sock in (self._stack_peer, self._client_end):
            sock.settimeout(5.0)
            self.addCleanup(sock.close)
        self.addCleanup(self._stack_inner.close)

        self._bridge = SocketBridge(_StackSocketStub(self._stack_inner), self._data_end)
        self._bridge.start()
        self.addCleanup(self._bridge.stop)

    def test__ipc__socket_bridge__rx_stack_to_client(self) -> None:
        """
        Ensure bytes arriving on the stack socket are pumped out to the
        client socketpair end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack_peer.sendall(b"downstream")

        self.assertEqual(
            self._client_end.recv(64),
            b"downstream",
            msg="The bridge must pump stack-socket RX data to the client end.",
        )

    def test__ipc__socket_bridge__tx_client_to_stack(self) -> None:
        """
        Ensure bytes the client writes are pumped into the stack socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client_end.sendall(b"upstream")

        self.assertEqual(
            self._stack_peer.recv(64),
            b"upstream",
            msg="The bridge must pump client-written bytes into the stack socket.",
        )

    def test__ipc__socket_bridge__bidirectional(self) -> None:
        """
        Ensure both directions pump independently over the same bridge.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack_peer.sendall(b"a")
        self._client_end.sendall(b"b")

        self.assertEqual(
            (self._client_end.recv(8), self._stack_peer.recv(8)),
            (b"a", b"b"),
            msg="The bridge must pump both directions independently.",
        )

    def test__ipc__socket_bridge__remote_close_signals_client_eof(self) -> None:
        """
        Ensure a remote close on the stack socket is propagated to the
        client end as end-of-stream (a half-close of the data channel).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack_peer.close()

        self.assertEqual(
            self._client_end.recv(8),
            b"",
            msg="A remote close must surface to the client end as EOF.",
        )

    def test__ipc__socket_bridge__client_close_signals_stack_fin(self) -> None:
        """
        Ensure a client half-close is propagated to the stack socket as
        a write-side shutdown (FIN).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client_end.shutdown(socket.SHUT_WR)

        self.assertEqual(
            self._stack_peer.recv(8),
            b"",
            msg="A client half-close must surface to the stack socket as a FIN.",
        )


class _ScriptedStackSocket:
    """
    A bridge stack-socket stub whose recv plays a scripted sequence: a
    'TimeoutError' sentinel raises (a poll timeout), bytes are returned
    as data, and the script's end yields b'' (a remote close) after a
    short idle so the pump terminates.
    """

    def __init__(self, script: list[object], /) -> None:
        self._script = script
        self._index = 0

    def recv(self, _bufsize: int, _timeout: float) -> bytes:
        """Play the next scripted recv result (or idle-then-EOF)."""

        if self._index < len(self._script):
            item = self._script[self._index]
            self._index += 1
            if item is TimeoutError:
                raise TimeoutError
            assert isinstance(item, bytes)
            return item
        time.sleep(0.02)
        return b""

    def send(self, data: bytes) -> int:
        """Discard sent bytes (the TX direction is not under test here)."""

        return len(data)

    def shutdown(self, _how: int, /) -> None:
        """No-op shutdown."""


class TestIpcSocketBridge__FaultInjection(TestCase):
    """
    Fault-injected pump behaviour that healthy socketpairs never reach:
    the RX pump must treat a poll TimeoutError as a retry (continue),
    not a teardown.
    """

    def test__socket_bridge__rx_pump_survives_poll_timeout(self) -> None:
        """
        Ensure the RX pump continues past a poll TimeoutError and still
        delivers the data that follows it — pinning the 'except
        TimeoutError: continue' branch against a teardown edit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(data_end.close)
        self.addCleanup(client_end.close)
        client_end.settimeout(3.0)

        stub = _ScriptedStackSocket([TimeoutError, b"after-timeout", b""])
        bridge = SocketBridge(stub, data_end)
        bridge.start()
        self.addCleanup(bridge.stop)

        self.assertEqual(
            client_end.recv(64),
            b"after-timeout",
            msg="data following a poll timeout must still reach the client (the pump must continue).",
        )
