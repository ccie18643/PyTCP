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
This module contains the daemon-side control-plane RPC dispatcher.

'handle_control_call' is the server handler for the 'CONTROL_CALL' op: it
decodes a control request, resolves the named API (and optional interface
scope), invokes the requested method with the decoded keyword arguments,
and encodes the result into a RESPONSE_OK message. Any exception the call
raises is forwarded faithfully as a RESPONSE_ERROR carrying the
exception's type name and message — the boundary translation a client
turns back into an 'IpcRemoteError'.

A wire-supplied method name is only ever invoked when it appears in the
per-API allowlist below — the dispatcher never reflects an arbitrary
attribute off a stack object.

pytcp/ipc/ipc__control.py

ver 3.0.10
"""

from typing import Any

from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__rpc import (
    ControlRequest,
    decode_control_request,
    encode_control_error,
    encode_control_ok,
)

# Per-API method allowlist. A wire-supplied method name is invoked only
# when it is a member here, so a malicious or buggy peer cannot reach a
# private method or dunder off a stack object. The 'interface' selector is
# absent — the client resolves it locally and threads the scope into the
# request's 'ifindex'. 'membership.set_socket_filter' / 'clear_socket_filter'
# are absent — they are daemon-internal socket plumbing, not user control.
_ALLOWED_METHODS: dict[str, frozenset[str]] = {
    "sysctl": frozenset(
        {"get", "set", "list_keys", "describe", "snapshot", "reset_to_defaults"},
    ),
    "route": frozenset(
        {"list_routes", "add_route", "remove_route", "replace_default", "remove_default"},
    ),
    "link": frozenset(
        {
            "list_interfaces",
            "set_mtu",
            "set_mac_address",
            "mac_address",
            "mtu",
            "name",
            "interface_layer",
            "is_running",
            "stats",
            "flags",
        },
    ),
    "address": frozenset({"add", "remove", "replace", "list_ifaddrs"}),
    "neighbor": frozenset({"add", "remove", "flush", "list_neighbors"}),
    "membership": frozenset({"join", "leave", "list_memberships"}),
    "resolver": frozenset({"resolve", "get_dns_server"}),
    "socket_introspect": frozenset({"list_sockets"}),
    "activity_introspect": frozenset({"list_activity"}),
}


def _resolve_api(name: str, /) -> Any:
    """
    Resolve a control-API name to the object its methods are called on.
    """

    from pytcp import stack

    match name:
        case "sysctl":
            from pytcp.stack import sysctl as sysctl_module

            return sysctl_module
        case "route":
            return stack.route
        case "link":
            return stack.link
        case "address":
            return stack.address
        case "neighbor":
            return stack.neighbor
        case "membership":
            return stack.membership
        case "resolver":
            return stack.resolver
        case "socket_introspect":
            return stack.ss
        case "activity_introspect":
            return stack.activity

    raise KeyError(f"Unknown control API {name!r}.")


def _invoke(control: ControlRequest, /) -> Any:
    """
    Resolve, scope, and invoke the requested control-API method.
    """

    allowed = _ALLOWED_METHODS.get(control.api)
    if allowed is None:
        raise KeyError(f"Unknown control API {control.api!r}.")
    if control.method not in allowed:
        raise KeyError(
            f"Method {control.method!r} is not permitted on control API {control.api!r}.",
        )

    api_object = _resolve_api(control.api)
    if control.ifindex is not None:
        api_object = api_object.interface(control.ifindex)

    target = getattr(api_object, control.method)

    # A method is called with the request's args; a read property (e.g.
    # 'LinkApi.mtu') resolves to its value directly and takes no args.
    if callable(target):
        return target(**control.args)

    return target


def handle_control_call(request: IpcMessage, /) -> IpcMessage:
    """
    Serve a 'CONTROL_CALL' request, returning the OK / ERROR response.
    """

    try:
        value = _invoke(decode_control_request(request.body))
    except Exception as error:  # pylint: disable=broad-exception-caught
        # The control boundary forwards any API failure faithfully as a
        # structured RESPONSE_ERROR; the client turns it back into an
        # 'IpcRemoteError'. This is translation, not silent swallowing.
        return IpcMessage(
            kind=IpcMessageKind.RESPONSE_ERROR,
            op=request.op,
            req_id=request.req_id,
            body=encode_control_error(error_type=type(error).__name__, message=str(error)),
        )

    return IpcMessage(
        kind=IpcMessageKind.RESPONSE_OK,
        op=request.op,
        req_id=request.req_id,
        body=encode_control_ok(value),
    )
