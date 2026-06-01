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
This module contains the pure CLI output formatters.

Each formatter turns a tuple of control-API snapshots into the faithful,
parseable text layout of its Linux counterpart ('ss', 'ip neighbor', 'ip
route', 'sysctl'). They are pure functions with no daemon dependency, so
they are golden-tested directly.

pytcp/cli/cli__format.py

ver 3.0.8
"""

from collections.abc import Iterable, Mapping, Sequence

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
from pytcp.runtime.fib import Route
from pytcp.runtime.socket import SocketType
from pytcp.stack.neighbor import NeighborSnapshot
from pytcp.stack.socket_introspect import SocketSnapshot

type _AnyRoute = Route[Ip4Address, Ip4Network] | Route[Ip6Address, Ip6Network]

# 'ss' Netid column values per socket type.
_NETID_BY_TYPE: dict[SocketType, str] = {
    SocketType.STREAM: "tcp",
    SocketType.DGRAM: "udp",
    SocketType.RAW: "raw",
}

# The default-route destinations, rendered as 'default' by 'ip route'.
_DEFAULT_DESTINATIONS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})


def _format_table(headers: Sequence[str], rows: Sequence[Sequence[str]], /) -> str:
    """
    Render a left-aligned text table with per-column widths sized to the
    widest cell (header included).
    """

    columns = [headers, *rows]
    widths = [max(len(row[index]) for row in columns) for index in range(len(headers))]

    return "\n".join("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in columns)


def _address_port(address: object, port: int, /) -> str:
    """
    Render an 'address:port' endpoint, using '*' for the wildcard port 0.
    """

    return f"{address}:{'*' if port == 0 else port}"


def format_socket_table(snapshots: Iterable[SocketSnapshot], /) -> str:
    """
    Render open sockets in the 'ss -tuln' table layout.
    """

    headers = ("Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port")
    rows = [
        (
            _NETID_BY_TYPE.get(snapshot.socket_type, str(snapshot.socket_type)),
            str(snapshot.state) if snapshot.state is not None else "UNCONN",
            str(snapshot.rx_queue),
            str(snapshot.tx_queue),
            _address_port(snapshot.local_address, snapshot.local_port),
            _address_port(snapshot.remote_address, snapshot.remote_port),
        )
        for snapshot in snapshots
    ]

    return _format_table(headers, rows)


def format_neighbor_table(snapshots: Iterable[NeighborSnapshot], /) -> str:
    """
    Render neighbour-cache entries in the 'ip neighbor show' line layout.
    """

    lines = []
    for snapshot in snapshots:
        if snapshot.mac_address is not None:
            lines.append(f"{snapshot.address} lladdr {snapshot.mac_address} {snapshot.state}")
        else:
            lines.append(f"{snapshot.address} {snapshot.state}")

    return "\n".join(lines)


def format_route_table(routes: Iterable[_AnyRoute], /) -> str:
    """
    Render routes in the 'ip route show' line layout.
    """

    lines = []
    for route in routes:
        destination = "default" if str(route.destination) in _DEFAULT_DESTINATIONS else str(route.destination)
        parts = [destination]
        if route.gateway is not None:
            parts += ["via", str(route.gateway)]
        if route.oif is not None:
            parts += ["dev", f"if{route.oif}"]
        parts += ["scope", route.scope.name.lower()]
        parts += ["proto", route.protocol.name.lower()]
        if route.prefsrc is not None:
            parts += ["src", str(route.prefsrc)]
        if route.metric:
            parts += ["metric", str(route.metric)]
        lines.append(" ".join(parts))

    return "\n".join(lines)


def format_sysctl(items: Mapping[str, object], /) -> str:
    """
    Render sysctl entries in the 'sysctl' 'key = value' line layout.
    """

    return "\n".join(f"{key} = {value}" for key, value in items.items())
