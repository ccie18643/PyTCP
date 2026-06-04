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
This module contains the IPC length-prefixed stream framing codec.

A byte stream (AF_UNIX) has no message boundaries; the IPC control
channel restores them by prefixing every payload with a 4-byte
big-endian unsigned length. This module is the lowest layer of the IPC
codec core — it depends only on the standard library and 'net_proto'
('Buffer'), reaching into no pytcp stack internals, so it stays liftable
into a standalone dist (see docs/refactor/kernel_userspace_separation.md
§2).

pytcp/ipc/ipc__frame.py

ver 3.0.8
"""

import struct

from net_proto.lib.buffer import Buffer
from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket

IPC__FRAME__LENGTH_PREFIX_STRUCT: str = "! I"
IPC__FRAME__LENGTH_PREFIX_LEN: int = 4
IPC__FRAME__MAX_PAYLOAD_LEN: int = 16 * 1024 * 1024


def pack_frame(payload: Buffer, /) -> bytes:
    """
    Prepend the 4-byte big-endian length prefix to a payload.
    """

    length = len(payload)

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        raise IpcFrameError(
            f"Frame payload length {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    return struct.pack(IPC__FRAME__LENGTH_PREFIX_STRUCT, length) + bytes(payload)


def send_frame(sock: stdlib_socket.socket, payload: Buffer, /) -> None:
    """
    Write a single length-prefixed frame to the stream stdlib_socket.
    """

    sock.sendall(pack_frame(payload))


def recv_frame(sock: stdlib_socket.socket, /) -> bytes | None:
    """
    Read a single length-prefixed frame from the stream stdlib_socket.

    Returns the payload bytes, or None when the peer closes the stream
    cleanly at a frame boundary (end of stream). Raises 'IpcFrameError'
    when the stream is closed mid-frame or the announced length exceeds
    the maximum.
    """

    prefix = recv_exactly(sock, IPC__FRAME__LENGTH_PREFIX_LEN)

    if len(prefix) == 0:
        return None

    if len(prefix) < IPC__FRAME__LENGTH_PREFIX_LEN:
        raise IpcFrameError(
            "Stream closed mid-frame while reading the 4-byte length prefix.",
        )

    length = int(struct.unpack(IPC__FRAME__LENGTH_PREFIX_STRUCT, prefix)[0])

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        raise IpcFrameError(
            f"Frame length prefix {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    payload = recv_exactly(sock, length)

    if len(payload) < length:
        raise IpcFrameError(
            f"Stream closed mid-frame: expected {length} payload bytes, " f"got {len(payload)}.",
        )

    return payload


def recv_exactly(sock: stdlib_socket.socket, count: int, /) -> bytes:
    """
    Read exactly 'count' bytes from the stream, looping over partial
    reads. Returns fewer than 'count' bytes only when the peer closes
    the stream before 'count' bytes arrive — the caller distinguishes a
    clean boundary EOF (zero bytes) from a mid-frame truncation (a
    non-zero short read) by the returned length.
    """

    chunks: list[bytes] = []
    remaining = count

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)
