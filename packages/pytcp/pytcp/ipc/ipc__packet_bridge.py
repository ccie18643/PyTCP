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
This module contains the daemon-side per-socket AF_PACKET bridge.

The link-layer analogue of 'DatagramBridge'. It shuttles whole frames
between a stack AF_PACKET socket and a SOCK_DGRAM socketpair end, framing
each with its 'sockaddr_ll' (see 'ipc__packet_frame') so the link-layer
address survives: the RX pump frames each captured frame with how it
arrived; the TX pump decodes the framed address and replays it as
'sendto'. Like the datagram bridge, an AF_PACKET socketpair has no
peer-close EOF, so teardown is 'stop'-driven from the control-channel
disconnect; a frame the stack refuses is dropped and the pumps keep
running.

pytcp/ipc/ipc__packet_bridge.py

ver 3.0.8
"""

import socket
import threading
from typing import Protocol

from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

IPC__PACKET_BRIDGE__POLL_TIMEOUT__SEC: float = 0.2
IPC__PACKET_BRIDGE__CHUNK_SIZE: int = 65600
IPC__PACKET_BRIDGE__JOIN_TIMEOUT__SEC: float = 2.0


class LinkSocket(Protocol):
    """
    The stack AF_PACKET-socket surface the packet bridge drives.
    """

    def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]:
        """
        Receive one frame with its 'sockaddr_ll', blocking up to
        'timeout' seconds.
        """

        ...

    def sendto(self, data: bytes, address: SockAddrLl) -> int:
        """
        Send 'data' as a link-layer frame to the interface named by
        'address'.
        """

        ...


class PacketBridge:
    """
    A bidirectional link-frame pump between a stack AF_PACKET socket and
    a SOCK_DGRAM socketpair end.
    """

    def __init__(self, packet_socket: LinkSocket, data_end: socket.socket, /) -> None:
        """
        Bind the bridge to a stack AF_PACKET socket and its client-facing
        SOCK_DGRAM socketpair end (left unstarted until 'start').
        """

        self._packet_socket = packet_socket
        self._data_end = data_end
        self._data_end.settimeout(IPC__PACKET_BRIDGE__POLL_TIMEOUT__SEC)
        self._event__stop = threading.Event()
        self._thread__rx: threading.Thread | None = None
        self._thread__tx: threading.Thread | None = None

    def start(self) -> None:
        """
        Spawn the RX and TX pump threads.
        """

        self._thread__rx = threading.Thread(target=self._pump_rx, name="IPC-PacketBridge-RX")
        self._thread__tx = threading.Thread(target=self._pump_tx, name="IPC-PacketBridge-TX")
        self._thread__rx.start()
        self._thread__tx.start()

    def _pump_rx(self) -> None:
        """
        Pump stack-captured frames out to the client, framed with their
        'sockaddr_ll'.
        """

        while not self._event__stop.is_set():
            try:
                frame, sockaddr_ll = self._packet_socket.recvfrom(None, IPC__PACKET_BRIDGE__POLL_TIMEOUT__SEC)
            except TimeoutError:
                continue
            except OSError:
                continue

            try:
                self._data_end.send(encode_packet(sockaddr_ll, frame))
            except OSError:
                break

    def _pump_tx(self) -> None:
        """
        Pump client-written frames into the stack, replaying each framed
        'sockaddr_ll' as 'sendto'.
        """

        while not self._event__stop.is_set():
            try:
                blob = self._data_end.recv(IPC__PACKET_BRIDGE__CHUNK_SIZE)
            except TimeoutError:
                continue
            except OSError:
                break

            if not blob:
                continue

            try:
                sockaddr_ll, frame = decode_packet(blob)
            except IpcFrameError:
                continue

            try:
                self._packet_socket.sendto(frame, sockaddr_ll)
            except OSError:
                # The stack refused the frame (e.g. no egress interface);
                # drop it and keep pumping.
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
                thread.join(timeout=IPC__PACKET_BRIDGE__JOIN_TIMEOUT__SEC)

        try:
            self._data_end.close()
        except OSError:
            pass
