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

ver 3.0.9
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
)
from pytcp.runtime.fib import Route
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.activity_introspect import InterfaceActivity
from pytcp.stack.neighbor import NeighborSnapshot
from pytcp.stack.socket_introspect import SocketSnapshot

type _AnyRoute = Route[Ip4Address, Ip4Network] | Route[Ip6Address, Ip6Network]


@dataclass(frozen=True, kw_only=True, slots=True)
class InterfaceView:
    """
    A per-interface view for the 'addr' / 'link' formatters — the link
    attributes plus the interface's assigned addresses.
    """

    ifindex: int
    name: str
    flags: tuple[str, ...]
    mtu: int
    mac_address: MacAddress | None
    addresses: tuple[Ip4IfAddr | Ip6IfAddr, ...]


# 'ss' Netid column values per socket type.
_NETID_BY_TYPE: dict[SocketType, str] = {
    SocketType.STREAM: "tcp",
    SocketType.DGRAM: "udp",
    SocketType.RAW: "raw",
}


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


def format_socket_table_json(snapshots: Iterable[SocketSnapshot], /) -> str:
    """
    Render open sockets as a JSON array — one object per socket with the
    'ss' columns as keys (netid / family / state / recv_q / send_q +
    local / peer address and port). An unconnected socket carries the
    'UNCONN' state string, matching the human table.
    """

    payload = [
        {
            "netid": _NETID_BY_TYPE.get(snapshot.socket_type, str(snapshot.socket_type)),
            "family": "inet6" if snapshot.address_family is AddressFamily.INET6 else "inet",
            "state": str(snapshot.state) if snapshot.state is not None else "UNCONN",
            "recv_q": snapshot.rx_queue,
            "send_q": snapshot.tx_queue,
            "local_address": str(snapshot.local_address),
            "local_port": snapshot.local_port,
            "peer_address": str(snapshot.remote_address),
            "peer_port": snapshot.remote_port,
        }
        for snapshot in snapshots
    ]

    return json.dumps(payload, indent=2)


# Neighbour-table row + column header, in the same table style as the
# route table. Each entry is a '(snapshot, device)' pair — the device is
# the interface the entry was learned on (the snapshot does not carry it).
_NEIGHBOR_TABLE__ROW = "{address:<30} {lladdr:<19} {state:<11} {device}"
_NEIGHBOR_TABLE__HEADER = _NEIGHBOR_TABLE__ROW.format(
    address="Address",
    lladdr="Link-Layer Address",
    state="State",
    device="Device",
)


def format_neighbor_table(entries: Iterable[tuple[NeighborSnapshot, str]], /) -> str:
    """
    Render neighbour-cache entries (column header + rows) in the same
    layout as the route table: 'Address', 'Link-Layer Address', 'State',
    'Device'. Each entry pairs a snapshot with the interface it was
    learned on. The caller supplies the section chrome.
    """

    lines = [_NEIGHBOR_TABLE__HEADER]
    for snapshot, device in entries:
        lines.append(
            _NEIGHBOR_TABLE__ROW.format(
                address=str(snapshot.address),
                lladdr=str(snapshot.mac_address) if snapshot.mac_address is not None else "",
                state=str(snapshot.state),
                device=device,
            )
        )

    return "\n".join(lines)


def format_neighbor_table_json(entries: Iterable[tuple[NeighborSnapshot, str]], /) -> str:
    """
    Render neighbour-cache entries as a JSON array mirroring the 'ip -j
    neighbor' object shape (dst / lladdr / dev / state). Each entry pairs
    a snapshot with the interface it was learned on; an unresolved entry
    carries a null 'lladdr'.
    """

    payload = [
        {
            "dst": str(snapshot.address),
            "lladdr": str(snapshot.mac_address) if snapshot.mac_address is not None else None,
            "dev": device,
            "state": str(snapshot.state),
        }
        for snapshot, device in entries
    ]

    return json.dumps(payload, indent=2)


def _route_iface(oif: int | None, names: Mapping[int, str], /) -> str:
    """
    Render a route's egress interface for the 'Iface' / 'If' column —
    the interface name when known, the raw 'ifN' form when the name map
    lacks it, and net-tools' '*' when the route has no egress interface.
    """

    if oif is None:
        return "*"
    return names.get(oif, f"if{oif}")


def _route_flags(route: _AnyRoute, /, *, host_prefixlen: int) -> str:
    """
    Render a route's net-tools flag string: 'U' (up — every listed
    route), '+G' when it has a gateway, '+H' when it is a host route.
    """

    flags = "U"
    if route.gateway is not None:
        flags += "G"
    if route.destination.prefixlen == host_prefixlen:
        flags += "H"
    return flags


# Unified route-table row + column header, shared by both families. The
# destination is CIDR ('x.x.x.x/n' / 'x::/n'); the netmask is encoded in
# the prefix length, so there is no separate Genmask column.
_ROUTE_TABLE__ROW = "{dst:<30} {gw:<26} {flags:<5} {metric:>6} {ref:>3} {use:>5} {iface}"
_ROUTE_TABLE__HEADER = _ROUTE_TABLE__ROW.format(
    dst="Destination",
    gw="Gateway",
    flags="Flags",
    metric="Metric",
    ref="Ref",
    use="Use",
    iface="Iface",
)


def format_route_table(
    routes: Iterable[_AnyRoute],
    /,
    *,
    family: AddressFamily,
    interface_names: Mapping[int, str] | None = None,
) -> str:
    """
    Render a routing-table body (column header + rows) in a layout shared
    by both families: 'Destination' (CIDR — 'x.x.x.x/n' for IPv4,
    'x::/n' for IPv6, so the default route renders as '0.0.0.0/0' /
    '::/0'), 'Gateway', 'Flags', 'Metric', 'Ref', 'Use', 'Iface'.
    'interface_names' maps an egress ifindex to its interface name; a
    route with no egress interface renders '*'. The caller supplies the
    section chrome.
    """

    names = interface_names or {}
    is_ip4 = family is AddressFamily.INET4
    host_prefixlen = 32 if is_ip4 else 128
    unspecified_gateway = "0.0.0.0" if is_ip4 else "::"

    lines = [_ROUTE_TABLE__HEADER]
    for route in routes:
        network = route.destination
        gateway = str(route.gateway) if route.gateway is not None else unspecified_gateway
        lines.append(
            _ROUTE_TABLE__ROW.format(
                dst=f"{network.address}/{network.prefixlen}",
                gw=gateway,
                flags=_route_flags(route, host_prefixlen=host_prefixlen),
                metric=route.metric,
                ref=0,
                use=0,
                iface=_route_iface(route.oif, names),
            )
        )

    return "\n".join(lines)


def format_route_table_json(
    routes: Iterable[_AnyRoute],
    /,
    *,
    interface_names: Mapping[int, str] | None = None,
) -> str:
    """
    Render routes as a JSON array mirroring the 'ip -j route' object shape
    (family / dst / gateway / dev / prefsrc / metric / scope / protocol).
    The family is inferred per route from its destination network; a
    route with no gateway / prefsrc carries a null field, and a route
    with no egress interface a null 'dev'. 'interface_names' maps an
    egress ifindex to its interface name.
    """

    names = interface_names or {}
    payload = [
        {
            "family": "inet" if isinstance(route.destination, Ip4Network) else "inet6",
            "dst": f"{route.destination.address}/{route.destination.prefixlen}",
            "gateway": str(route.gateway) if route.gateway is not None else None,
            "dev": names.get(route.oif, f"if{route.oif}") if route.oif is not None else None,
            "prefsrc": str(route.prefsrc) if route.prefsrc is not None else None,
            "metric": route.metric,
            "scope": route.scope.name.lower(),
            "protocol": route.protocol.name.lower(),
        }
        for route in routes
    ]

    return json.dumps(payload, indent=2)


def flatten_sysctl(items: Mapping[str, object], /) -> dict[str, object]:
    """
    Expand interface-scope knobs into a flat scalar map. Such a knob
    arrives as a '{slot: value}' storage dict keyed by the base
    '<namespace>.<field>' name; it is expanded in place to one
    '<namespace>.<slot>.<field>' -> value entry per slot — the
    'default' template slot first, then each per-interface slot in
    sorted order — mirroring the Linux 'sysctl -a' per-interface
    layout. Flat entries pass through unchanged. Insertion order is
    preserved so a dump keeps its registration order.
    """

    result: dict[str, object] = {}
    for key, value in items.items():
        if isinstance(value, Mapping):
            prefix, _, field = key.rpartition(".")
            slots = [slot for slot in ("default",) if slot in value]
            slots += sorted(slot for slot in value if slot != "default")
            for slot in slots:
                result[f"{prefix}.{slot}.{field}"] = value[slot]
        else:
            result[key] = value
    return result


def format_sysctl(items: Mapping[str, object], /) -> str:
    """
    Render sysctl entries in the 'sysctl' 'key = value' line layout.
    Interface-scope knobs are flattened to one fully-qualified
    '<namespace>.<slot>.<field>' line per slot (see 'flatten_sysctl').
    """

    return "\n".join(f"{key} = {value}" for key, value in flatten_sysctl(items).items())


def _interface_lines(view: InterfaceView, *, with_addresses: bool) -> list[str]:
    """
    Render one interface's 'ip link' / 'ip addr' lines.
    """

    lines = [f"{view.ifindex}: {view.name}: <{','.join(view.flags)}> mtu {view.mtu}"]
    if view.mac_address is not None:
        lines.append(f"    link/ether {view.mac_address}")
    if with_addresses:
        for address in view.addresses:
            family = "inet" if isinstance(address, Ip4IfAddr) else "inet6"
            lines.append(f"    {family} {address}")
    return lines


def format_link(views: Iterable[InterfaceView], /) -> str:
    """
    Render interfaces in the 'ip link show' layout (no addresses).
    """

    return "\n".join(line for view in views for line in _interface_lines(view, with_addresses=False))


def format_addr(views: Iterable[InterfaceView], /) -> str:
    """
    Render interfaces with their addresses in the 'ip addr show' layout.
    """

    return "\n".join(line for view in views for line in _interface_lines(view, with_addresses=True))


def format_addr_json(views: Iterable[InterfaceView], /) -> str:
    """
    Render interfaces with their addresses as a JSON array, mirroring the
    'ip -j addr show' object shape (ifindex / ifname / flags / mtu /
    address + per-address 'addr_info' with family / local / prefixlen).
    """

    payload = [
        {
            "ifindex": view.ifindex,
            "ifname": view.name,
            "flags": list(view.flags),
            "mtu": view.mtu,
            "address": str(view.mac_address) if view.mac_address is not None else None,
            "addr_info": [
                {
                    "family": "inet" if isinstance(address, Ip4IfAddr) else "inet6",
                    "local": str(address.address),
                    "prefixlen": address.network.prefixlen,
                }
                for address in view.addresses
            ],
        }
        for view in views
    ]

    return json.dumps(payload, indent=2)


def format_activity(activities: Iterable[InterfaceActivity]) -> str:
    """
    Render the per-interface ongoing-autoconfig 'Activity:' section for
    'pytcp daemon status' — the DHCPv4 FSM state and any DAD-in-progress
    IPv6 addresses. Interfaces with no DHCPv4 client and no tentative
    address are omitted; an empty string is returned when nothing is
    active, so the caller can skip the section entirely.
    """

    lines: list[str] = []
    for activity in activities:
        parts: list[str] = []
        if activity.dhcp4_state is not None:
            parts.append(f"dhcp4 {activity.dhcp4_state}")
        if activity.tentative_ip6:
            parts.append("tentative " + ", ".join(str(address) for address in activity.tentative_ip6))
        if parts:
            lines.append(f"  {activity.name}: {'; '.join(parts)}")

    if not lines:
        return ""
    return "Activity:\n" + "\n".join(lines)
