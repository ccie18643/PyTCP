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
This module contains the IPC control-plane RPC body codec.

A control-plane call is one 'CONTROL_CALL' message. Its request body is a
JSON document naming the target API, method, optional interface scope, and
encoded keyword arguments; its response body is a JSON document carrying
either the encoded return value (RESPONSE_OK) or the remote exception's
type and message (RESPONSE_ERROR). This module encodes / decodes those
bodies and provides 'control_call', the client-side helper that issues a
call over an 'IpcClient' and returns the decoded value (or raises
'IpcRemoteError' on a remote failure).

pytcp/ipc/ipc__rpc.py

ver 3.0.9
"""

import json
from dataclasses import dataclass
from typing import Any, NoReturn

from net_addr import Buffer
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__errors import IpcConnectionError, IpcRemoteError
from pytcp.ipc.ipc__values import decode_value, encode_value


@dataclass(frozen=True, kw_only=True, slots=True)
class ControlRequest:
    """
    A decoded control-plane RPC request: which API method to call, on
    which optional interface scope, with which keyword arguments.
    """

    api: str
    method: str
    ifindex: int | None
    args: dict[str, Any]


def encode_control_request(
    *,
    api: str,
    method: str,
    ifindex: int | None,
    args: dict[str, Any],
) -> bytes:
    """
    Encode a control-plane request into a JSON body.
    """

    return json.dumps(
        {
            "api": api,
            "method": method,
            "ifindex": ifindex,
            "args": {key: encode_value(value) for key, value in args.items()},
        }
    ).encode()


def decode_control_request(body: Buffer, /) -> ControlRequest:
    """
    Decode a control-plane request from its JSON body.
    """

    document = json.loads(bytes(body))

    return ControlRequest(
        api=document["api"],
        method=document["method"],
        ifindex=document["ifindex"],
        args={key: decode_value(value) for key, value in document["args"].items()},
    )


def encode_control_ok(value: Any, /) -> bytes:
    """
    Encode a successful control-plane result into a JSON body.
    """

    return json.dumps({"value": encode_value(value)}).encode()


def encode_control_error(*, error_type: str, message: str) -> bytes:
    """
    Encode a control-plane failure into a JSON body.
    """

    return json.dumps({"error": error_type, "message": message}).encode()


def decode_control_value(body: Buffer, /) -> Any:
    """
    Decode a successful control-plane result from its JSON body.
    """

    return decode_value(json.loads(bytes(body))["value"])


def raise_control_error(body: Buffer, /) -> NoReturn:
    """
    Raise an 'IpcRemoteError' from a control-plane error body.
    """

    document = json.loads(bytes(body))

    raise IpcRemoteError(
        error_type=document["error"],
        message=document["message"],
    )


def control_call(
    client: IpcClient,
    /,
    *,
    api: str,
    method: str,
    ifindex: int | None,
    args: dict[str, Any],
) -> Any:
    """
    Issue a control-plane call over the client and return its decoded
    result, raising 'IpcRemoteError' if the daemon reported a failure.
    """

    response = client.request(
        IpcOp.CONTROL_CALL,
        body=encode_control_request(api=api, method=method, ifindex=ifindex, args=args),
    )

    if response.kind is IpcMessageKind.RESPONSE_OK:
        return decode_control_value(response.body)

    if response.kind is IpcMessageKind.RESPONSE_ERROR:
        raise_control_error(response.body)

    raise IpcConnectionError(
        f"Daemon returned an unexpected response kind {response.kind!r} to a control call.",
    )
