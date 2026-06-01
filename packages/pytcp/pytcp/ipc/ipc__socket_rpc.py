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
This module contains the IPC socket-syscall RPC body codec.

A socket syscall is one 'SOCKET_CALL' message. Its request body is a JSON
document naming the socket method, the per-client socket handle it acts on
(None for the handle-allocating 'socket' call), and encoded keyword
arguments; its response body is a JSON document carrying either the
encoded return value (RESPONSE_OK) or the remote exception's type and
message (RESPONSE_ERROR). The 'socket' call's response additionally
carries a passed file descriptor on the control stream (see
'ipc__fdpass'), so its data channel is established in the same round trip.

This codec is the socket-plane analogue of the control-plane codec in
'ipc__rpc'; it shares the tagged value codec and the 'IpcRemoteError'
boundary translation but keeps a distinct request shape.

pytcp/ipc/ipc__socket_rpc.py

ver 3.0.8
"""

import json
import os
from dataclasses import dataclass
from typing import Any, NoReturn

from net_proto.lib.buffer import Buffer
from net_proto.lib.enums import EtherType, IpProto
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__errors import IpcConnectionError, IpcRemoteError
from pytcp.ipc.ipc__values import decode_value, encode_value
from pytcp.socket import AddressFamily, SocketType


@dataclass(frozen=True, kw_only=True, slots=True)
class SocketRequest:
    """
    A decoded socket-syscall RPC request: which socket method to call, on
    which per-client socket handle (None for the handle-allocating
    'socket' call), with which keyword arguments.
    """

    method: str
    handle: int | None
    args: dict[str, Any]


def encode_socket_request(
    *,
    method: str,
    handle: int | None,
    args: dict[str, Any],
) -> bytes:
    """
    Encode a socket-syscall request into a JSON body.
    """

    return json.dumps(
        {
            "method": method,
            "handle": handle,
            "args": {key: encode_value(value) for key, value in args.items()},
        }
    ).encode()


def decode_socket_request(body: Buffer, /) -> SocketRequest:
    """
    Decode a socket-syscall request from its JSON body.
    """

    document = json.loads(bytes(body))

    return SocketRequest(
        method=document["method"],
        handle=document["handle"],
        args={key: decode_value(value) for key, value in document["args"].items()},
    )


def encode_socket_ok(value: Any, /) -> bytes:
    """
    Encode a successful socket-syscall result into a JSON body.
    """

    return json.dumps({"value": encode_value(value)}).encode()


def encode_socket_error(*, error_type: str, message: str) -> bytes:
    """
    Encode a socket-syscall failure into a JSON body.
    """

    return json.dumps({"error": error_type, "message": message}).encode()


def decode_socket_value(body: Buffer, /) -> Any:
    """
    Decode a successful socket-syscall result from its JSON body.
    """

    return decode_value(json.loads(bytes(body))["value"])


def raise_socket_error(body: Buffer, /) -> NoReturn:
    """
    Raise an 'IpcRemoteError' from a socket-syscall error body.
    """

    document = json.loads(bytes(body))

    raise IpcRemoteError(
        error_type=document["error"],
        message=document["message"],
    )


def socket_call(
    client: IpcClient,
    /,
    *,
    method: str,
    handle: int,
    args: dict[str, Any],
) -> Any:
    """
    Issue a handle-keyed (non-fd) socket call over the client and return
    its decoded result, raising 'IpcRemoteError' if the daemon reported a
    failure.
    """

    response = client.request(
        IpcOp.SOCKET_CALL,
        body=encode_socket_request(method=method, handle=handle, args=args),
    )

    if response.kind is IpcMessageKind.RESPONSE_OK:
        return decode_socket_value(response.body)

    if response.kind is IpcMessageKind.RESPONSE_ERROR:
        raise_socket_error(response.body)

    raise IpcConnectionError(
        f"Daemon returned an unexpected response kind {response.kind!r} to a socket call.",
    )


def open_socket(
    client: IpcClient,
    /,
    *,
    family: AddressFamily,
    type_: SocketType,
    protocol: IpProto | EtherType | int | None = None,
) -> tuple[int, int]:
    """
    Issue the fd-bearing 'socket' call and return '(handle, data_fd)',
    where 'data_fd' is the passed data-channel descriptor the client owns.
    A raw IP socket supplies its IANA next-header 'protocol'; an AF_PACKET
    socket supplies its ethertype filter.

    Raises 'IpcRemoteError' on a remote failure (the fd-less error path)
    and closes any stray passed descriptor before raising.
    """

    args: dict[str, Any] = {"family": family, "type": type_}
    if protocol is not None:
        args["protocol"] = protocol

    response, fd = client.request_with_fd(
        IpcOp.SOCKET_CALL,
        body=encode_socket_request(method="socket", handle=None, args=args),
    )

    if response.kind is IpcMessageKind.RESPONSE_OK:
        if fd is None:
            raise IpcConnectionError("Daemon opened a socket but passed no data-channel descriptor.")
        return int(decode_socket_value(response.body)["handle"]), fd

    if fd is not None:
        os.close(fd)

    if response.kind is IpcMessageKind.RESPONSE_ERROR:
        raise_socket_error(response.body)

    raise IpcConnectionError(
        f"Daemon returned an unexpected response kind {response.kind!r} to a socket-open call.",
    )


def accept_socket(client: IpcClient, /, *, handle: int) -> tuple[int, tuple[str, int], int]:
    """
    Issue the blocking fd-bearing 'accept' call on a listening socket and
    return '(child_handle, peer_address, data_fd)' for the accepted
    connection, where 'data_fd' is the passed data-channel descriptor the
    client owns.

    Raises 'IpcRemoteError' on a remote failure (the fd-less error path)
    and closes any stray passed descriptor before raising.
    """

    response, fd = client.request_with_fd(
        IpcOp.SOCKET_CALL,
        body=encode_socket_request(method="accept", handle=handle, args={}),
        blocking=True,
    )

    if response.kind is IpcMessageKind.RESPONSE_OK:
        if fd is None:
            raise IpcConnectionError("Daemon accepted a connection but passed no data-channel descriptor.")
        value = decode_socket_value(response.body)
        peer = value["peer"]
        return int(value["handle"]), (peer[0], peer[1]), fd

    if fd is not None:
        os.close(fd)

    if response.kind is IpcMessageKind.RESPONSE_ERROR:
        raise_socket_error(response.body)

    raise IpcConnectionError(
        f"Daemon returned an unexpected response kind {response.kind!r} to an accept call.",
    )
