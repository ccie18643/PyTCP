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
This module contains the IPC control-plane tagged value codec.

The control-plane RPC (Phase 1) carries each call's arguments and result
as a JSON document. JSON has no native representation for the typed
values the control APIs traffic in — net_addr addresses / networks /
interface addresses, control-plane enums, and the frozen introspection
snapshots — so this codec maps every such value to and from a
self-describing tagged form:

    {"__t__": "<type-tag>", "v": <json-native payload>}

'encode_value' turns a typed value into JSON-native structures (the
tagged form for typed values, bare for primitives and lists);
'decode_value' is its inverse. Together with json.dumps / json.loads
(applied by the RPC layer) this round-trips a control-plane value across
the process boundary.

Unlike the transport primitives (frame / message / enums), this module
references stack snapshot types (Route / NeighborSnapshot / LinkStats)
and is therefore pytcp-resident, not part of the extraction-ready codec
core (see docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__values.py

ver 3.0.8
"""

import base64
import dataclasses
from enum import Enum
from typing import Any

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Mask,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Mask,
    Ip6Network,
    MacAddress,
)
from net_proto.lib.enums import EtherType, IpProto
from pytcp.ipc.ipc__errors import IpcValueError
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.neighbor import NudState
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.fib import Route, RouteProtocol, RouteScope
from pytcp.runtime.socket import (
    AddressFamily,
    IpOption,
    IpV6Option,
    MsgFlag,
    PacketType,
    SocketOption,
    SocketType,
    SolLevel,
    SolSocketOption,
)
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl
from pytcp.stack.link import LinkFlag, LinkStats
from pytcp.stack.neighbor import NeighborSnapshot
from pytcp.stack.socket_introspect import SocketSnapshot

_TAG_KEY: str = "__t__"
_VAL_KEY: str = "v"

# net_addr value types — encoded as their canonical str() and rebuilt by
# passing that string back to the constructor.
_STR_TYPES: tuple[type[Any], ...] = (
    Ip4Address,
    Ip6Address,
    MacAddress,
    Ip4Network,
    Ip6Network,
    Ip4IfAddr,
    Ip6IfAddr,
    Ip4Mask,
    Ip6Mask,
)
_STR_TYPE_BY_TAG: dict[str, type[Any]] = {t.__name__: t for t in _STR_TYPES}

# Control-plane and socket-option enums — encoded by member name,
# rebuilt by name lookup. The socket-option levels / names cross
# faithfully as members (not bare ints) because an IPPROTO_* level is an
# 'IpProto' ProtoEnum, which is deliberately not equal to its integer —
# the daemon's '==' option dispatch only matches a member, never an int.
_ENUM_TYPES: tuple[type[Enum], ...] = (
    AddressFamily,
    RouteProtocol,
    RouteScope,
    NudState,
    InterfaceLayer,
    LinkFlag,
    IpProto,
    EtherType,
    SocketType,
    PacketType,
    SolLevel,
    SocketOption,
    SolSocketOption,
    IpOption,
    IpV6Option,
    MsgFlag,
    FsmState,
)
_ENUM_TYPE_BY_TAG: dict[str, type[Enum]] = {t.__name__: t for t in _ENUM_TYPES}

# Frozen introspection snapshots — encoded field-by-field, rebuilt by
# keyword construction.
_DATACLASS_TYPES: tuple[type[Any], ...] = (
    Route,
    NeighborSnapshot,
    LinkStats,
    SockAddrLl,
    SocketSnapshot,
)
_DATACLASS_TYPE_BY_TAG: dict[str, type[Any]] = {t.__name__: t for t in _DATACLASS_TYPES}


def encode_value(value: Any, /) -> Any:
    """
    Encode a control-plane value into JSON-native structures.
    """

    # Enums first — IntEnum members are also 'int', so the primitive
    # branch below would otherwise flatten them to a bare integer.
    if isinstance(value, Enum):
        if type(value) in _ENUM_TYPE_BY_TAG.values():
            return {_TAG_KEY: type(value).__name__, _VAL_KEY: value.name}
        raise IpcValueError(
            f"Cannot encode value of unsupported enum type {type(value).__name__!r}.",
        )

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    # Raw bytes (e.g. a setsockopt value / getsockopt return) — encoded
    # as a base64 ASCII string since JSON has no byte-string form.
    if isinstance(value, (bytes, bytearray)):
        return {_TAG_KEY: "bytes", _VAL_KEY: base64.b64encode(bytes(value)).decode("ascii")}

    if isinstance(value, list):
        return [encode_value(item) for item in value]

    if isinstance(value, tuple):
        return {_TAG_KEY: "tuple", _VAL_KEY: [encode_value(item) for item in value]}

    if isinstance(value, frozenset):
        return {_TAG_KEY: "frozenset", _VAL_KEY: [encode_value(item) for item in value]}

    if isinstance(value, dict):
        return {
            _TAG_KEY: "dict",
            _VAL_KEY: {key: encode_value(item) for key, item in value.items()},
        }

    if isinstance(value, _STR_TYPES):
        return {_TAG_KEY: type(value).__name__, _VAL_KEY: str(value)}

    if (
        dataclasses.is_dataclass(value)
        and not isinstance(value, type)
        and type(value) in _DATACLASS_TYPE_BY_TAG.values()
    ):
        return {
            _TAG_KEY: type(value).__name__,
            _VAL_KEY: {field.name: encode_value(getattr(value, field.name)) for field in dataclasses.fields(value)},
        }

    raise IpcValueError(
        f"Cannot encode value of unsupported type {type(value).__name__!r}.",
    )


def decode_value(data: Any, /) -> Any:
    """
    Decode a control-plane value from its JSON-native encoding.
    """

    if isinstance(data, list):
        return [decode_value(item) for item in data]

    if isinstance(data, dict):
        if _TAG_KEY not in data:
            raise IpcValueError("Cannot decode object without a type tag.")

        tag = data[_TAG_KEY]
        payload = data[_VAL_KEY]

        if tag == "bytes":
            return base64.b64decode(payload)

        if tag == "tuple":
            return tuple(decode_value(item) for item in payload)

        if tag == "frozenset":
            return frozenset(decode_value(item) for item in payload)

        if tag == "dict":
            return {key: decode_value(item) for key, item in payload.items()}

        if (str_type := _STR_TYPE_BY_TAG.get(tag)) is not None:
            return str_type(payload)

        if (enum_type := _ENUM_TYPE_BY_TAG.get(tag)) is not None:
            return enum_type[payload]

        if (dataclass_type := _DATACLASS_TYPE_BY_TAG.get(tag)) is not None:
            return dataclass_type(**{key: decode_value(item) for key, item in payload.items()})

        raise IpcValueError(f"Cannot decode value with unknown type tag {tag!r}.")

    return data
