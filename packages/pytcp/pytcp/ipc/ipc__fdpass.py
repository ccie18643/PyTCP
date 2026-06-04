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
This module contains the IPC SCM_RIGHTS file-descriptor-passing primitive.

The data plane gives each client socket its own real, selectable fd: the
daemon creates a socketpair and passes one end to the client over the
control channel via an SCM_RIGHTS ancillary message. This module is that
transfer — a length-prefixed frame whose 4-byte prefix 'sendmsg' carries
exactly one descriptor, the payload following as a normal stream. The
receiver 'recvmsg's the prefix to capture the descriptor, then reads the
payload. Pinning the descriptor to the fixed-size prefix keeps capture
independent of the payload length.

pytcp/ipc/ipc__fdpass.py

ver 3.0.8
"""

import array
import os
import struct

from net_proto.lib.buffer import Buffer
from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__frame import (
    IPC__FRAME__LENGTH_PREFIX_LEN,
    IPC__FRAME__LENGTH_PREFIX_STRUCT,
    IPC__FRAME__MAX_PAYLOAD_LEN,
    recv_exactly,
)
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket

IPC__FDPASS__FD_STRUCT: str = "i"


def send_frame_with_fd(sock: stdlib_socket.socket, payload: Buffer, fd: int, /) -> None:
    """
    Send a length-prefixed frame with a file descriptor attached.

    The descriptor rides the prefix's 'sendmsg' as an SCM_RIGHTS
    ancillary message; the payload follows as a normal stream write.
    """

    length = len(payload)

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        raise IpcFrameError(
            f"Frame payload length {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    prefix = struct.pack(IPC__FRAME__LENGTH_PREFIX_STRUCT, length)
    sock.sendmsg(
        [prefix],
        [(stdlib_socket.SOL_SOCKET, stdlib_socket.SCM_RIGHTS, array.array(IPC__FDPASS__FD_STRUCT, [fd]))],
    )
    sock.sendall(bytes(payload))


def recv_frame_with_fd(sock: stdlib_socket.socket, /) -> tuple[bytes, int | None]:
    """
    Receive a length-prefixed frame and the descriptor attached to it.

    Returns '(payload, fd)' where 'fd' is the received descriptor (a new
    descriptor in this process), or None when the frame carried no
    descriptor — an fd-less RESPONSE_ERROR on the otherwise fd-bearing
    socket-creation path is the canonical case. Raises 'IpcFrameError' on
    a truncated or oversize frame, or when the prefix carried more than
    one descriptor; a received descriptor is closed before raising so it
    does not leak.
    """

    prefix, fd = _recv_prefix_with_fd(sock)

    length = int(struct.unpack(IPC__FRAME__LENGTH_PREFIX_STRUCT, prefix)[0])

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        if fd is not None:
            os.close(fd)
        raise IpcFrameError(
            f"Frame length prefix {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    payload = recv_exactly(sock, length)

    if len(payload) < length:
        if fd is not None:
            os.close(fd)
        raise IpcFrameError(
            f"Stream closed mid-frame: expected {length} payload bytes, " f"got {len(payload)}.",
        )

    return payload, fd


def _recv_prefix_with_fd(sock: stdlib_socket.socket, /) -> tuple[bytes, int | None]:
    """
    Read the length prefix, capturing the SCM_RIGHTS descriptor if one is
    attached (zero or one; more than one is a protocol error).
    """

    chunks: list[bytes] = []
    fds = array.array(IPC__FDPASS__FD_STRUCT)
    remaining = IPC__FRAME__LENGTH_PREFIX_LEN
    ancillary_size = stdlib_socket.CMSG_SPACE(struct.calcsize(IPC__FDPASS__FD_STRUCT))

    while remaining > 0:
        data, ancillary, _, _ = sock.recvmsg(remaining, ancillary_size)
        if not data:
            break
        chunks.append(data)
        remaining -= len(data)
        for level, ctype, cdata in ancillary:
            if level == stdlib_socket.SOL_SOCKET and ctype == stdlib_socket.SCM_RIGHTS:
                fds.frombytes(cdata[: len(cdata) - (len(cdata) % fds.itemsize)])

    prefix = b"".join(chunks)

    if len(prefix) < IPC__FRAME__LENGTH_PREFIX_LEN:
        for fd in fds:
            os.close(fd)
        raise IpcFrameError(
            "Stream closed mid-frame while reading the 4-byte length prefix.",
        )

    if len(fds) > 1:
        for fd in fds:
            os.close(fd)
        raise IpcFrameError(
            f"Expected at most one passed file descriptor, received {len(fds)}.",
        )

    return prefix, (fds[0] if fds else None)
