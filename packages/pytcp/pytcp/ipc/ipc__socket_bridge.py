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
This module contains the daemon-side per-socket data bridge.

When a client opens a stream socket the daemon creates a socketpair, hands
one end to the client as its real socket fd, and runs a 'SocketBridge'
shuttling bytes between the other end and the internal stack socket. Two
blocking pump threads carry the two directions: RX (stack socket ->
client) and TX (client -> stack socket). Each blocks on a short-timeout
read so it can re-check the stop flag, and propagates a half-close (a
'recv' of b"") as a 'shutdown' on the far side. Backpressure falls out of
the socketpair: a slow reader blocks the pump, which stalls the stack
socket and closes the TCP window.

pytcp/ipc/ipc__socket_bridge.py

ver 3.0.8
"""

import socket
import threading
import time
from typing import Protocol

IPC__BRIDGE__POLL_TIMEOUT__SEC: float = 0.2
IPC__BRIDGE__CHUNK_SIZE: int = 65536
IPC__BRIDGE__JOIN_TIMEOUT__SEC: float = 2.0
# Wall-clock bound on draining the non-blocking-connect priming filler so
# a client that under-fills its send buffer cannot wedge the connect worker.
IPC__BRIDGE__PRIME_DRAIN_DEADLINE__SEC: float = 2.0


class BridgedSocket(Protocol):
    """
    The stack-socket surface the data bridge drives.
    """

    def recv(self, bufsize: int, timeout: float) -> bytes:
        """
        Receive up to 'bufsize' bytes, blocking up to 'timeout' seconds.
        """

        ...

    def send(self, data: bytes) -> int:
        """
        Send some of 'data', returning the number of bytes accepted.
        """

        ...

    def shutdown(self, how: int, /) -> None:
        """
        Shut down one or both halves of the connection.
        """


class SocketBridge:
    """
    A bidirectional byte pump between a stack socket and a socketpair end.
    """

    def __init__(self, stack_socket: BridgedSocket, data_end: socket.socket, /) -> None:
        """
        Bind the bridge to a stack socket and its client-facing socketpair
        end (left unstarted until 'start').
        """

        self._stack_socket = stack_socket
        self._data_end = data_end
        self._data_end.settimeout(IPC__BRIDGE__POLL_TIMEOUT__SEC)
        self._event__stop = threading.Event()
        self._thread__rx: threading.Thread | None = None
        self._thread__tx: threading.Thread | None = None

    def start(self) -> None:
        """
        Spawn the RX and TX pump threads.
        """

        self._thread__rx = threading.Thread(target=self._pump_rx, name="IPC-Bridge-RX")
        self._thread__tx = threading.Thread(target=self._pump_tx, name="IPC-Bridge-TX")
        self._thread__rx.start()
        self._thread__tx.start()

    def prime_drain(self, byte_count: int, /) -> None:
        """
        Read and discard exactly 'byte_count' non-blocking-connect priming
        bytes from the client socketpair end, flipping the client fd
        writable on connect resolution. Bounded by a wall-clock deadline so
        a client that under-fills its send buffer cannot wedge the worker;
        swallows a closed-socket error so a connect cancelled by teardown
        unwinds cleanly.
        """

        if byte_count <= 0:
            return

        deadline = time.monotonic() + IPC__BRIDGE__PRIME_DRAIN_DEADLINE__SEC
        drained = 0
        while drained < byte_count and time.monotonic() < deadline:
            try:
                chunk = self._data_end.recv(min(IPC__BRIDGE__CHUNK_SIZE, byte_count - drained))
            except TimeoutError:
                continue
            except OSError:
                return
            if not chunk:
                return
            drained += len(chunk)

    def _pump_rx(self) -> None:
        """
        Pump stack-socket RX data out to the client socketpair end.
        """

        while not self._event__stop.is_set():
            try:
                data = self._stack_socket.recv(IPC__BRIDGE__CHUNK_SIZE, IPC__BRIDGE__POLL_TIMEOUT__SEC)
            except TimeoutError:
                continue
            except OSError:
                break

            if not data:
                # Remote closed — signal end-of-stream to the client by
                # half-closing the write side of its socketpair end.
                try:
                    self._data_end.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                break

            try:
                self._data_end.sendall(data)
            except OSError:
                break

    def _pump_tx(self) -> None:
        """
        Pump client-written bytes into the stack socket.
        """

        while not self._event__stop.is_set():
            try:
                data = self._data_end.recv(IPC__BRIDGE__CHUNK_SIZE)
            except TimeoutError:
                continue
            except OSError:
                break

            if not data:
                # Client half-closed — propagate as a FIN on the stack
                # socket's write side.
                try:
                    self._stack_socket.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                break

            if not self._send_all(data):
                break

    def _send_all(self, data: bytes, /) -> bool:
        """
        Send every byte of 'data' into the stack socket; return False on
        a send error so the caller can stop the pump.
        """

        offset = 0
        while offset < len(data):
            try:
                offset += self._stack_socket.send(data[offset:])
            except OSError:
                return False
        return True

    def stop(self) -> None:
        """
        Stop both pump threads and close the client-facing socketpair end.
        """

        self._event__stop.set()
        # Interrupt a pump blocked in 'data_end' I/O (e.g. a backpressured
        # 'sendall') so it observes the stop flag promptly.
        try:
            self._data_end.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        for thread in (self._thread__rx, self._thread__tx):
            if thread is not None:
                thread.join(timeout=IPC__BRIDGE__JOIN_TIMEOUT__SEC)

        try:
            self._data_end.close()
        except OSError:
            pass
