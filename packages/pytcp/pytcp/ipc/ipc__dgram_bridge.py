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
This module contains the daemon-side per-socket datagram bridge.

The datagram analogue of 'SocketBridge': it shuttles whole datagrams
between a stack datagram socket and a SOCK_DGRAM socketpair end. Two
blocking pump threads carry the two directions — RX (stack 'recvfrom' ->
client) frames each datagram with its sender address; TX (client ->
stack) decodes the framed address and replays it as 'sendto' (or 'send'
for a connected socket). A datagram socket has no peer-close EOF (a
SOCK_DGRAM socketpair read just times out when the far end closes), so
teardown is driven by 'stop' from the control-channel disconnect, not by
a data-channel signal. A datagram the stack refuses (e.g. no route) is
dropped — UDP is best-effort — and the pumps keep running.

pytcp/ipc/ipc__dgram_bridge.py

ver 3.0.8
"""

import socket
import threading
from typing import Protocol

from pytcp.ipc.ipc__dgram_frame import decode_dgram, encode_dgram
from pytcp.ipc.ipc__errors import IpcFrameError

IPC__DGRAM_BRIDGE__POLL_TIMEOUT__SEC: float = 0.2
IPC__DGRAM_BRIDGE__CHUNK_SIZE: int = 65600
IPC__DGRAM_BRIDGE__JOIN_TIMEOUT__SEC: float = 2.0
# Ancillary-data buffer the RX pump offers 'recvmsg', large enough for
# the data-path cmsgs PyTCP emits (IP_TOS / IPV6_TCLASS / IP_OPTIONS).
IPC__DGRAM_BRIDGE__ANCBUF_SIZE: int = 256


class DatagramSocket(Protocol):
    """
    The stack datagram-socket surface the datagram bridge drives.
    """

    def recvmsg(
        self,
        bufsize: int | None,
        ancbufsize: int,
        flags: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive one datagram with its ancillary data and sender address,
        blocking up to 'timeout' seconds.
        """

        ...

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send 'data' as a datagram to 'address'.
        """

        ...

    def send(self, data: bytes) -> int:
        """
        Send 'data' as a datagram to the connected peer.
        """

        ...


class DatagramBridge:
    """
    A bidirectional datagram pump between a stack datagram socket and a
    SOCK_DGRAM socketpair end.
    """

    def __init__(self, dgram_socket: DatagramSocket, data_end: socket.socket, /) -> None:
        """
        Bind the bridge to a stack datagram socket and its client-facing
        SOCK_DGRAM socketpair end (left unstarted until 'start').
        """

        self._dgram_socket = dgram_socket
        self._data_end = data_end
        self._data_end.settimeout(IPC__DGRAM_BRIDGE__POLL_TIMEOUT__SEC)
        self._event__stop = threading.Event()
        self._thread__rx: threading.Thread | None = None
        self._thread__tx: threading.Thread | None = None

    def start(self) -> None:
        """
        Spawn the RX and TX pump threads.
        """

        self._thread__rx = threading.Thread(target=self._pump_rx, name="IPC-DgramBridge-RX")
        self._thread__tx = threading.Thread(target=self._pump_tx, name="IPC-DgramBridge-TX")
        self._thread__rx.start()
        self._thread__tx.start()

    def _pump_rx(self) -> None:
        """
        Pump stack-received datagrams out to the client, framed with the
        sender address and any ancillary control messages.
        """

        while not self._event__stop.is_set():
            try:
                data, ancdata, _flags, address = self._dgram_socket.recvmsg(
                    None,
                    IPC__DGRAM_BRIDGE__ANCBUF_SIZE,
                    0,
                    IPC__DGRAM_BRIDGE__POLL_TIMEOUT__SEC,
                )
            except TimeoutError:
                continue
            except OSError:
                # A transient receive error (e.g. a cached ICMP
                # unreachable surfaced as ConnectionRefusedError, which
                # clears itself) — skip this read and keep pumping.
                continue

            try:
                self._data_end.send(encode_dgram((address[0], address[1]), data, ancdata))
            except OSError:
                break

    def _pump_tx(self) -> None:
        """
        Pump client-written datagrams into the stack, replaying each
        framed address as 'sendto' (or 'send' for a connected socket).
        """

        while not self._event__stop.is_set():
            try:
                blob = self._data_end.recv(IPC__DGRAM_BRIDGE__CHUNK_SIZE)
            except TimeoutError:
                continue
            except OSError:
                break

            if not blob:
                continue

            try:
                # The send side honours no cmsg in PyTCP, so the framed
                # ancillary data (if any) is decoded and ignored here.
                address, _cmsg, payload = decode_dgram(blob)
            except IpcFrameError:
                continue

            try:
                if address is None:
                    self._dgram_socket.send(payload)
                else:
                    self._dgram_socket.sendto(payload, address)
            except OSError:
                # The stack refused the datagram (e.g. no route, or no
                # destination on a connected-less send) — drop it; UDP
                # is best-effort, so keep the pump running.
                continue

    def stop(self) -> None:
        """
        Stop both pump threads and close the client-facing socketpair end.
        """

        self._event__stop.set()
        try:
            self._data_end.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        for thread in (self._thread__rx, self._thread__tx):
            if thread is not None:
                thread.join(timeout=IPC__DGRAM_BRIDGE__JOIN_TIMEOUT__SEC)

        try:
            self._data_end.close()
        except OSError:
            pass
