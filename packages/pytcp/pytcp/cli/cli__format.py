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


def _format_route_table_ip4(routes: Iterable[_AnyRoute], /, *, names: Mapping[int, str], numeric: bool) -> str:
    """
    Render the IPv4 routing table in the net-tools 'route' layout.
    """

    lines = [
        "PyTCP IP routing table",
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface",
    ]
    for route in routes:
        network = route.destination
        if network.prefixlen == 0:
            destination = "0.0.0.0" if numeric else "default"
        else:
            destination = str(network.address)
        gateway = str(route.gateway) if route.gateway is not None else "0.0.0.0"
        # 'Ip4Mask.__str__' is the '/N' prefix form; net-tools' Genmask
        # column is the dotted-decimal netmask, so render the mask's
        # integer value through an Ip4Address.
        genmask = str(Ip4Address(int(network.mask)))
        flags = _route_flags(route, host_prefixlen=32)
        ref = use = 0
        lines.append(
            f"{destination:<16}{gateway:<16}{genmask:<16}"
            f"{flags:<6}{route.metric:<6} {ref:<2} {use:>7} {_route_iface(route.oif, names)}"
        )

    return "\n".join(lines)


def _format_route_table_ip6(routes: Iterable[_AnyRoute], /, *, names: Mapping[int, str]) -> str:
    """
    Render the IPv6 routing table in the net-tools 'route -6' layout.
    """

    lines = [
        "PyTCP IPv6 routing table",
        "Destination                    Next Hop                   Flag Met Ref  Use If",
    ]
    for route in routes:
        network = route.destination
        address = str(network.address)
        destination = f"{'[::]' if address == '::' else address}/{network.prefixlen}"
        nexthop = str(route.gateway) if route.gateway is not None else "[::]"
        flag = _route_flags(route, host_prefixlen=128)
        ref = use = 0
        lines.append(
            f"{destination:<30} {nexthop:<26} {flag:<4} "
            f"{route.metric:>4} {ref:>5} {use:>7} {_route_iface(route.oif, names)}"
        )

    return "\n".join(lines)


def format_route_table(
    routes: Iterable[_AnyRoute],
    /,
    *,
    family: AddressFamily,
    numeric: bool = False,
    interface_names: Mapping[int, str] | None = None,
) -> str:
    """
    Render routes in the net-tools 'route' table layout, one address
    family at a time — the 'route' (IPv4) / 'route -6' (IPv6) output.
    'numeric' mirrors 'route -n': the IPv4 default route's destination
    renders as '0.0.0.0' rather than 'default'. 'interface_names' maps
    an egress ifindex to its interface name for the 'Iface' / 'If'
    column; a route with no egress interface renders '*'. The header
    says 'PyTCP' where net-tools says 'Kernel' — PyTCP is the kernel.
    """

    names = interface_names or {}
    if family is AddressFamily.INET6:
        return _format_route_table_ip6(routes, names=names)
    return _format_route_table_ip4(routes, names=names, numeric=numeric)


def format_sysctl(items: Mapping[str, object], /) -> str:
    """
    Render sysctl entries in the 'sysctl' 'key = value' line layout.
    """

    return "\n".join(f"{key} = {value}" for key, value in items.items())


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
