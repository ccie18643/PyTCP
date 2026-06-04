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
This module contains the unified 'pytcp' CLI multitool.

'pytcp' is the operator front-end to a running PyTCP stack daemon: 'pytcp
ss' (sockets), 'pytcp route' (show / add / del routes), 'pytcp sysctl'
(tunables), 'pytcp address' / 'link' / 'neighbor', and 'pytcp stack start' (run
the stack daemon). The observation subcommands open a short-lived control
connection, call the matching 'ClientStack' API, and render the result
through the pure formatters in 'cli__format'.

pytcp/cli/__main__.py

ver 3.0.8
"""

import argparse
import os
import re
import signal
import sys
from collections.abc import Callable
from typing import Any, cast, override

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
    NetAddrError,
)
from pytcp import __version__
from pytcp.cli.cli__format import (
    InterfaceView,
    flatten_sysctl,
    format_activity,
    format_addr,
    format_link,
    format_neighbor_table,
    format_route_table,
    format_socket_table,
    format_sysctl,
)
from pytcp.client import ClientStack, connect
from pytcp.daemon.daemon import (
    default_pidfile_path,
    default_socket_path,
    remove_pidfile,
    run_daemon,
)
from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.runtime.fib import Route, RouteProtocol, RouteScope
from pytcp.runtime.socket import AddressFamily, SocketType


def _parse_sysctl_value(text: str, /) -> bool | int | str:
    """
    Parse a sysctl assignment value into a bool, int, or string.
    """

    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(text)
    except ValueError:
        return text


def _cmd_ss(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render the socket table for the 'ss' subcommand — the 'route'-style
    report with an overall header and per-family 'IPv4' / 'IPv6'
    sections. '-t' / '-u' filter by socket type, '-l' to listening only,
    '-4' / '-6' to one family.
    """

    socket_type: SocketType | None = None
    if args.tcp and not args.udp:
        socket_type = SocketType.STREAM
    elif args.udp and not args.tcp:
        socket_type = SocketType.DGRAM

    return _format_family_sections(
        "PyTCP Socket Table",
        _selected_families(args),
        lambda family: format_socket_table(
            client.ss.list_sockets(family=family, socket_type=socket_type, listening_only=args.listening)
        ),
    )


def _interface_names(client: ClientStack, /) -> dict[int, str]:
    """
    Map each interface's ifindex to its name for the 'dev' column.
    """

    return {
        ifindex: (client.link.interface(ifindex).name or f"if{ifindex}") for ifindex in client.link.list_interfaces()
    }


def _resolve_interface(client: ClientStack, dev: str, /, *, command: str) -> int:
    """
    Resolve an interface name to its index, erroring (under the named
    command) when no interface matches.
    """

    for ifindex in client.link.list_interfaces():
        if (client.link.interface(ifindex).name or f"if{ifindex}") == dev:
            return ifindex
    raise SystemExit(f"pytcp {command}: unknown interface {dev!r}.")


def _route_dev_oif(client: ClientStack, dev: str | None, /) -> int | None:
    """
    Resolve a route's '--dev' egress interface to its index, or 'None'
    when no '--dev' was given. Errors on an unknown interface name.
    """

    return None if dev is None else _resolve_interface(client, dev, command="route")


def _route_destination_is_ipv6(args: argparse.Namespace, /) -> bool:
    """
    Whether a 'route add' / 'route del' targets IPv6 — inferred from the
    destination (a ':' makes it IPv6), then from the '--via' gateway for a
    'default' target, then from the '-6' / '-A inet6' family hint.
    """

    if args.destination != "default":
        return ":" in args.destination
    if args.via is not None:
        return ":" in args.via
    return bool(args.inet6)


def _ip4_network(destination: str, /) -> Ip4Network:
    """
    Build an IPv4 network from a CIDR destination, or a host route (/32)
    from a bare address.
    """

    return Ip4Network(destination if "/" in destination else f"{destination}/32")


def _ip6_network(destination: str, /) -> Ip6Network:
    """
    Build an IPv6 prefix from a CIDR destination, or a host route (/128)
    from a bare address.
    """

    return Ip6Network(destination if "/" in destination else f"{destination}/128")


def _route_add_ip4(client: ClientStack, args: argparse.Namespace, *, oif: int | None) -> None:
    """
    Apply an IPv4 'route add' against the daemon's FIB.
    """

    if args.destination == "default":
        if args.via is None:
            raise SystemExit("pytcp route: 'add default' requires a gateway (--via).")
        client.route.replace_default(gateway=Ip4Address(args.via), protocol=RouteProtocol.STATIC, oif=oif)
        return
    gateway = Ip4Address(args.via) if args.via is not None else None
    scope = RouteScope.UNIVERSE if gateway is not None else RouteScope.LINK
    client.route.add_route(
        route=Route(
            destination=_ip4_network(args.destination),
            gateway=gateway,
            oif=oif,
            metric=args.metric,
            scope=scope,
            protocol=RouteProtocol.STATIC,
        )
    )


def _route_add_ip6(client: ClientStack, args: argparse.Namespace, *, oif: int | None) -> None:
    """
    Apply an IPv6 'route add' against the daemon's FIB.
    """

    if args.destination == "default":
        if args.via is None:
            raise SystemExit("pytcp route: 'add default' requires a gateway (--via).")
        client.route.replace_default(gateway=Ip6Address(args.via), protocol=RouteProtocol.STATIC, oif=oif)
        return
    gateway = Ip6Address(args.via) if args.via is not None else None
    scope = RouteScope.UNIVERSE if gateway is not None else RouteScope.LINK
    client.route.add_route(
        route=Route(
            destination=_ip6_network(args.destination),
            gateway=gateway,
            oif=oif,
            metric=args.metric,
            scope=scope,
            protocol=RouteProtocol.STATIC,
        )
    )


def _route_del_ip4(client: ClientStack, args: argparse.Namespace, /) -> None:
    """
    Apply an IPv4 'route del' against the daemon's FIB.
    """

    if args.destination == "default":
        client.route.remove_default(family=AddressFamily.INET4)
        return
    gateway = Ip4Address(args.via) if args.via is not None else None
    client.route.remove_route(destination=_ip4_network(args.destination), gateway=gateway)


def _route_del_ip6(client: ClientStack, args: argparse.Namespace, /) -> None:
    """
    Apply an IPv6 'route del' against the daemon's FIB.
    """

    if args.destination == "default":
        client.route.remove_default(family=AddressFamily.INET6)
        return
    gateway = Ip6Address(args.via) if args.via is not None else None
    client.route.remove_route(destination=_ip6_network(args.destination), gateway=gateway)


def _route_add(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Run a 'route add' against the daemon's FIB; returns an empty string (a
    successful modification prints nothing).
    """

    oif = _route_dev_oif(client, args.dev)
    try:
        if _route_destination_is_ipv6(args):
            _route_add_ip6(client, args, oif=oif)
        else:
            _route_add_ip4(client, args, oif=oif)
    except NetAddrError as error:
        raise SystemExit(f"pytcp route: {error}") from error
    return ""


def _route_del(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Run a 'route del' against the daemon's FIB; returns an empty string (a
    successful modification prints nothing).
    """

    try:
        if _route_destination_is_ipv6(args):
            _route_del_ip6(client, args)
        else:
            _route_del_ip4(client, args)
    except NetAddrError as error:
        raise SystemExit(f"pytcp route: {error}") from error
    return ""


def _selected_families(args: argparse.Namespace, /) -> tuple[AddressFamily, ...]:
    """
    The address families a '-4' / '-6'-bearing command should act on:
    just IPv6 with '-6', just IPv4 with '-4', both with neither.
    """

    if args.inet6:
        return (AddressFamily.INET6,)
    if args.inet:
        return (AddressFamily.INET4,)
    return (AddressFamily.INET4, AddressFamily.INET6)


def _format_family_sections(
    title: str,
    families: tuple[AddressFamily, ...],
    render: Callable[[AddressFamily], str],
    /,
) -> str:
    """
    Assemble a 'route'-style report shared by 'route' / 'neighbor' / 'ss':
    an overall bright-white 'title', then a bright-white 'IPv4' / 'IPv6'
    label per family followed by that family's table body ('render'
    returns 'column-header\\n<rows>'). The title, labels and column
    headers are highlighted on a TTY; row content keeps the terminal
    default.
    """

    sections = [_hl(title)]
    for family in families:
        label = "IPv4" if family is AddressFamily.INET4 else "IPv6"
        column_header, _, rows = render(family).partition("\n")
        section = f"{_hl(label)}\n{_hl(column_header)}"
        sections.append(f"{section}\n{rows}" if rows else section)
    return "\n\n".join(sections)


def _cmd_route_list(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render the routing table for a bare 'route' (no add / del). With no
    family flag both the IPv4 and IPv6 tables are shown; '-4' / '-6'
    narrow to one.
    """

    names = _interface_names(client)
    return _format_family_sections(
        "PyTCP Routing Table",
        _selected_families(args),
        lambda family: format_route_table(
            client.route.list_routes(family=family), family=family, interface_names=names
        ),
    )


def _cmd_sysctl(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Read or write a sysctl value, describe a key, or list all, for the
    'sysctl' subcommand. '--describe KEY' prints the knob's registered
    one-line description (an interface-scope knob may be addressed by
    its base or any slot-qualified form — the description is knob-level).
    """

    if args.describe:
        if args.key is None or "=" in args.key:
            raise SystemExit("pytcp sysctl: '--describe' requires a key (not 'key=value').")
        description = client.sysctl.describe(args.key)
        return f"{args.key}: {description or '(no description)'}"
    if args.key is None:
        return format_sysctl(client.sysctl.snapshot())
    if "=" in args.key:
        key, _, value = args.key.partition("=")
        client.sysctl.set(key, _parse_sysctl_value(value))
        return ""

    # A bare key reads like Linux 'sysctl': an exact readable leaf (a
    # flat key or a slot-qualified interface-scope key) reads that one
    # value; anything else is treated as a namespace prefix and lists
    # the matching subtree (so an interface-scope base key lists its
    # slots, and a namespace lists everything under it).
    snapshot = client.sysctl.snapshot()
    flattened = flatten_sysctl(snapshot)
    if args.key in flattened:
        return f"{args.key} = {flattened[args.key]}"
    matches = {key: value for key, value in snapshot.items() if key == args.key or key.startswith(f"{args.key}.")}
    if matches:
        return format_sysctl(matches)
    raise SystemExit(f"pytcp sysctl: no keys match {args.key!r}.")


def _interface_views(client: ClientStack, /) -> list[InterfaceView]:
    """
    Gather a per-interface link + address view for every interface.
    """

    views = []
    for ifindex in client.link.list_interfaces():
        link = client.link.interface(ifindex)
        flags = sorted(flag.name for flag in link.flags)
        if link.is_running:
            flags.append("UP")
        views.append(
            InterfaceView(
                ifindex=ifindex,
                name=link.name or "?",
                flags=tuple(flags),
                mtu=link.mtu,
                mac_address=link.mac_address,
                addresses=client.address.interface(ifindex).list_ifaddrs(),
            )
        )
    return views


def _cmd_neighbor_list(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render the neighbour caches for a bare 'neighbor' — an overall 'PyTCP
    Neighbor Table' header with per-family 'IPv4' / 'IPv6' sections, the
    same shape as 'route'. '-4' / '-6' narrow to one family. Each entry
    carries the interface it was learned on as its 'Device'.
    """

    names = _interface_names(client)

    def render(family: AddressFamily) -> str:
        entries = [
            (snapshot, names[ifindex])
            for ifindex in client.link.list_interfaces()
            for snapshot in client.neighbor.interface(ifindex).list_neighbors(family=family)
        ]
        return format_neighbor_table(entries)

    return _format_family_sections("PyTCP Neighbor Table", _selected_families(args), render)


def _cmd_neighbor_flush(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Flush the neighbour caches across every interface — Linux 'ip neighbor
    flush'. '-4' / '-6' restrict the flush to one family. Quiet on
    success (no output), like the route mutation verbs.
    """

    for family in _selected_families(args):
        for ifindex in client.link.list_interfaces():
            client.neighbor.interface(ifindex).flush(family=family)
    return ""


def _neighbor_ip(address: str, /) -> Ip4Address | Ip6Address:
    """
    Parse a neighbour's IP address, inferring the family from a ':'.
    """

    try:
        return Ip6Address(address) if ":" in address else Ip4Address(address)
    except NetAddrError as error:
        raise SystemExit(f"pytcp neighbor: {error}") from error


def _cmd_neighbor_add(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Add a static neighbour entry on '--dev' — Linux 'ip neighbor add ADDR
    lladdr MAC dev IF nud permanent'. Quiet on success.
    """

    ifindex = _resolve_interface(client, args.dev, command="neighbor")
    try:
        mac = MacAddress(args.lladdr)
    except NetAddrError as error:
        raise SystemExit(f"pytcp neighbor: {error}") from error
    client.neighbor.interface(ifindex).add(ip=_neighbor_ip(args.address), mac=mac)
    return ""


def _cmd_neighbor_del(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Delete a neighbour entry on '--dev' — Linux 'ip neighbor del ADDR dev
    IF'. Quiet on success (a no-op when no entry matches).
    """

    ifindex = _resolve_interface(client, args.dev, command="neighbor")
    client.neighbor.interface(ifindex).remove(ip=_neighbor_ip(args.address))
    return ""


def _cmd_address(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render interfaces with their addresses for a bare 'address'.
    """

    _ = args
    return format_addr(_interface_views(client))


def _cmd_address_add(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Add an interface address on '--dev' through the stack's Address API —
    Linux 'ip addr add ADDR/PREFIX dev IF'. An IPv6 address is run
    through Duplicate Address Detection before it is installed (the
    Address API's default); an IPv4 address installs directly. Quiet on
    success.
    """

    ifindex = _resolve_interface(client, args.dev, command="address")
    try:
        ifaddr: Ip4IfAddr | Ip6IfAddr = Ip6IfAddr(args.ifaddr) if ":" in args.ifaddr else Ip4IfAddr(args.ifaddr)
    except NetAddrError as error:
        raise SystemExit(f"pytcp address: {error}") from error
    client.address.interface(ifindex).add(ifaddr=ifaddr)
    return ""


def _cmd_address_del(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Remove an interface address on '--dev' through the stack's Address
    API — Linux 'ip addr del ADDR dev IF'. The host part identifies the
    address; the API aborts any TCP session bound to it (RFC 5227 §2.4).
    Quiet on success.
    """

    ifindex = _resolve_interface(client, args.dev, command="address")
    try:
        address: Ip4Address | Ip6Address = Ip6Address(args.address) if ":" in args.address else Ip4Address(args.address)
    except NetAddrError as error:
        raise SystemExit(f"pytcp address: {error}") from error
    client.address.interface(ifindex).remove(address=address)
    return ""


def _cmd_link(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render interfaces without addresses for a bare 'link'.
    """

    _ = args
    return format_link(_interface_views(client))


def _cmd_link_set(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Set interface attributes on '--dev' — Linux 'ip link set dev IF [mtu
    N] [address MAC]'. Setting the MAC requires the stack to be stopped
    (the daemon rejects it otherwise). Quiet on success.
    """

    ifindex = _resolve_interface(client, args.dev, command="link")
    if args.mtu is None and args.mac is None:
        raise SystemExit("pytcp link: 'set' requires --mtu and/or --mac.")
    link = client.link.interface(ifindex)
    if args.mtu is not None:
        link.set_mtu(mtu=args.mtu)
    if args.mac is not None:
        try:
            mac = MacAddress(args.mac)
        except NetAddrError as error:
            raise SystemExit(f"pytcp link: {error}") from error
        link.set_mac_address(mac_address=mac)
    return ""


_BANNER = f"PyTCP - Python TCP/IP Stack v{__version__}"

# ANSI: bold bright-white, used for the banner and the help section
# headings. argparse's own 3.14 help colourisation is disabled
# ('color=False' below), so body content keeps the terminal's default
# colour. Emitted to a TTY only (see '_PytcpArgumentParser.format_help').
_ANSI__HIGHLIGHT = "\033[1;97m"
_ANSI__RESET = "\033[0m"

# A section-heading line — 'usage:' (with text after it) or a standalone
# 'options:' / 'commands:' / 'positional arguments:' line.
_HEADING__RE = re.compile(r"^(usage:|[A-Za-z][\w ]*:$)", re.MULTILINE)


def _hl(text: str, /) -> str:
    """
    Wrap a header line in bold bright-white on a TTY; leave it plain
    otherwise (so piped / captured output stays uncoloured).
    """

    return f"{_ANSI__HIGHLIGHT}{text}{_ANSI__RESET}" if sys.stdout.isatty() else text


def _highlight_help_headings(text: str, /) -> str:
    """
    Wrap the 'usage:' prefix and each standalone section heading
    ('options:', 'commands:', ...) in bold bright-white, leaving the body
    content untouched.
    """

    return _HEADING__RE.sub(lambda match: f"{_ANSI__HIGHLIGHT}{match.group(1)}{_ANSI__RESET}", text)


class _PytcpHelpFormatter(argparse.HelpFormatter):
    """
    Help formatter that drops the subparsers' redundant '<command>'
    metavar header line, leaving the per-command entries listed directly
    under the 'commands:' section.
    """

    @override
    def _format_action(self, action: argparse.Action) -> str:
        formatted = super()._format_action(action)
        if action.nargs == argparse.PARSER:
            formatted = "\n".join(formatted.split("\n")[1:])
        return formatted


class _PytcpArgumentParser(argparse.ArgumentParser):
    """
    An argument parser whose help leads with the bold bright-white PyTCP
    banner (with version), set off by a blank line before and after, and
    renders the section headings ('usage:' / 'options:' / 'commands:') in
    bold bright-white too. argparse's own 3.14 help colourisation is
    turned off ('color=False'), so body content keeps the terminal
    default. Subparsers inherit this class (argparse defaults a
    subparser's 'parser_class' to its parent's type) and its
    '_PytcpHelpFormatter', so every help screen is consistent. Colour is
    emitted only to a TTY, so piped or captured help stays plain text.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _PytcpHelpFormatter)
        kwargs.setdefault("color", False)
        super().__init__(*args, **kwargs)

    @override
    def format_help(self) -> str:
        # Set off with a blank line before the banner and a trailing blank
        # line after the help.
        body = super().format_help()
        if not sys.stdout.isatty():
            return f"\n{_BANNER}\n\n{body}\n"
        banner = f"{_ANSI__HIGHLIGHT}{_BANNER}{_ANSI__RESET}"
        return f"\n{banner}\n\n{_highlight_help_headings(body)}\n"


def build_parser() -> argparse.ArgumentParser:
    """
    Build the 'pytcp' multitool argument parser.
    """

    parser = _PytcpArgumentParser(
        prog="pytcp",
        description="Operator front-end to a running PyTCP stack daemon.",
    )
    parser.add_argument(
        "--ipc-socket",
        default=default_socket_path(),
        help="AF_UNIX control-socket path (default: $XDG_RUNTIME_DIR/pytcp.sock).",
    )
    parser.add_argument("-V", "--version", action="version", version=f"pytcp {__version__}")

    # Observation commands talk to the daemon and so run through the
    # shared connect path; the 'stack' lifecycle commands override this.
    parser.set_defaults(needs_client=True)

    subparsers = parser.add_subparsers(dest="command", required=True, title="commands", metavar="<command>")

    parser_ss = subparsers.add_parser("ss", help="Show socket statistics.")
    parser_ss.add_argument("-t", "--tcp", action="store_true", help="Show only TCP sockets.")
    parser_ss.add_argument("-u", "--udp", action="store_true", help="Show only UDP sockets.")
    parser_ss.add_argument("-l", "--listening", action="store_true", help="Show only listening sockets.")
    parser_ss.add_argument("-4", dest="inet", action="store_true", help="Show only IPv4 sockets.")
    parser_ss.add_argument("-6", dest="inet6", action="store_true", help="Show only IPv6 sockets.")
    parser_ss.set_defaults(func=_cmd_ss)

    parser_route = subparsers.add_parser("route", help="Show or modify the routing table.")
    parser_route.add_argument("-4", dest="inet", action="store_true", help="Show only the IPv4 routing table.")
    parser_route.add_argument("-6", dest="inet6", action="store_true", help="Show only the IPv6 routing table.")
    # A bare 'route' (no add / del subcommand) lists the table.
    parser_route.set_defaults(func=_cmd_route_list)
    route_subparsers = parser_route.add_subparsers(dest="route_command", title="commands", metavar="<command>")
    for verb, verb_help in (("add", "Add a route."), ("del", "Delete a route.")):
        parser_verb = route_subparsers.add_parser(verb, help=verb_help)
        parser_verb.add_argument(
            "destination",
            metavar="DEST",
            help="A CIDR ('10.9.0.0/24'), a host address ('10.0.0.5'), or 'default'.",
        )
        parser_verb.add_argument(
            "-g",
            "--via",
            metavar="GATEWAY",
            help="Next-hop gateway address." if verb == "add" else "Only act on the route via this gateway.",
        )
        if verb == "add":
            parser_verb.add_argument("-i", "--dev", metavar="IFACE", help="Egress interface name.")
            parser_verb.add_argument("--metric", type=int, default=0, help="Route metric (default 0).")
        parser_verb.set_defaults(func=_route_add if verb == "add" else _route_del)

    parser_neighbor = subparsers.add_parser("neighbor", help="Show or flush the neighbour caches.")
    parser_neighbor.add_argument("-4", dest="inet", action="store_true", help="Only IPv4 (ARP) neighbours.")
    parser_neighbor.add_argument("-6", dest="inet6", action="store_true", help="Only IPv6 (ND) neighbours.")
    parser_neighbor.set_defaults(func=_cmd_neighbor_list)
    neighbor_subparsers = parser_neighbor.add_subparsers(dest="neighbor_command", title="commands", metavar="<command>")
    parser_neighbor_add = neighbor_subparsers.add_parser("add", help="Add a static neighbour entry.")
    parser_neighbor_add.add_argument("address", metavar="ADDRESS", help="The neighbour's IP address.")
    parser_neighbor_add.add_argument(
        "-l", "--lladdr", required=True, metavar="MAC", help="The link-layer (MAC) address."
    )
    parser_neighbor_add.add_argument("-i", "--dev", required=True, metavar="IFACE", help="The interface.")
    parser_neighbor_add.set_defaults(func=_cmd_neighbor_add)
    parser_neighbor_del = neighbor_subparsers.add_parser("del", help="Delete a neighbour entry.")
    parser_neighbor_del.add_argument("address", metavar="ADDRESS", help="The neighbour's IP address.")
    parser_neighbor_del.add_argument("-i", "--dev", required=True, metavar="IFACE", help="The interface.")
    parser_neighbor_del.set_defaults(func=_cmd_neighbor_del)
    parser_neighbor_flush = neighbor_subparsers.add_parser("flush", help="Flush the neighbour caches.")
    parser_neighbor_flush.set_defaults(func=_cmd_neighbor_flush)
    parser_address = subparsers.add_parser("address", help="Show, add, or remove interface addresses.")
    parser_address.set_defaults(func=_cmd_address)
    address_subparsers = parser_address.add_subparsers(dest="address_command", title="commands", metavar="<command>")
    parser_address_add = address_subparsers.add_parser("add", help="Add an interface address.")
    parser_address_add.add_argument(
        "ifaddr", metavar="ADDRESS/PREFIX", help="The interface address in CIDR form (e.g. 10.0.1.50/24)."
    )
    parser_address_add.add_argument("-i", "--dev", required=True, metavar="IFACE", help="The interface.")
    parser_address_add.set_defaults(func=_cmd_address_add)
    parser_address_del = address_subparsers.add_parser("del", help="Remove an interface address.")
    parser_address_del.add_argument("address", metavar="ADDRESS", help="The host address to remove (e.g. 10.0.1.50).")
    parser_address_del.add_argument("-i", "--dev", required=True, metavar="IFACE", help="The interface.")
    parser_address_del.set_defaults(func=_cmd_address_del)
    parser_link = subparsers.add_parser("link", help="Show or configure interfaces.")
    link_subparsers = parser_link.add_subparsers(dest="link_command", title="commands", metavar="<command>")
    parser_link_set = link_subparsers.add_parser("set", help="Set interface attributes (Linux 'ip link set').")
    parser_link_set.add_argument("-i", "--dev", required=True, metavar="IFACE", help="The interface.")
    parser_link_set.add_argument("--mtu", type=int, metavar="BYTES", help="Set the interface MTU.")
    parser_link_set.add_argument("--mac", metavar="MAC", help="Set the interface MAC address (stack must be stopped).")
    parser_link_set.set_defaults(func=_cmd_link_set)
    parser_link.set_defaults(func=_cmd_link)

    parser_sysctl = subparsers.add_parser("sysctl", help="Read or write sysctl values.")
    parser_sysctl.add_argument(
        "key",
        nargs="?",
        default=None,
        help="A sysctl key to read, 'key=value' to set, or omit to list all.",
    )
    parser_sysctl.add_argument(
        "-d",
        "--describe",
        action="store_true",
        help="Print the key's registered description instead of its value.",
    )
    parser_sysctl.set_defaults(func=_cmd_sysctl)

    parser_stack = subparsers.add_parser("stack", help="Manage the PyTCP stack daemon.")
    stack_subparsers = parser_stack.add_subparsers(
        dest="stack_command", required=True, title="commands", metavar="<command>"
    )
    parser_start = stack_subparsers.add_parser("start", help="Start the stack daemon in the foreground.")
    parser_start.add_argument(
        "-i",
        "--interface",
        action="append",
        metavar="INTERFACE",
        help="TAP/TUN interface to bind to; repeat for a multi-homed host (default: tap7).",
    )
    parser_start.add_argument("--pidfile", default=default_pidfile_path(), help="Pidfile path for 'stack stop'.")
    parser_start.set_defaults(func=_cmd_stack_start, needs_client=False)
    parser_stop = stack_subparsers.add_parser("stop", help="Stop the stack daemon via its pidfile.")
    parser_stop.add_argument("--pidfile", default=default_pidfile_path(), help="Pidfile path to signal.")
    parser_stop.set_defaults(func=_cmd_stack_stop, needs_client=False)

    parser_status = stack_subparsers.add_parser(
        "status",
        help="Show whether the stack daemon is running and its state (exit 0 running, 3 not running).",
    )
    parser_status.add_argument("--pidfile", default=default_pidfile_path(), help="Pidfile path to read.")
    parser_status.set_defaults(func=_cmd_stack_status, needs_client=False)

    return parser


def _read_pidfile(pidfile_path: str, /) -> int | None:
    """
    Read the recorded pid from the pidfile, or None when the pidfile is
    absent or does not contain an integer.
    """

    try:
        with open(pidfile_path, encoding="ascii") as handle:
            return int(handle.read().strip())
    except FileNotFoundError, ValueError:
        return None


def _process_alive(pid: int, /) -> bool:
    """
    Whether a process with the given pid currently exists, probed with the
    null signal (which checks for the process without sending anything).
    """

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # The process exists but is owned by another user.
        return True
    return True


def _stop_stack(pidfile_path: str, /) -> int:
    """
    Signal a running daemon to stop via its pidfile, cleaning up a stale
    pidfile if the process is gone.
    """

    pid = _read_pidfile(pidfile_path)
    if pid is None:
        print("PyTCP stack is not running (no pidfile).", file=sys.stderr)
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        remove_pidfile(pidfile_path)
        print(f"PyTCP stack (pid {pid}) is not running; removed stale pidfile.", file=sys.stderr)
        return 1

    print(f"Sent SIGTERM to PyTCP stack (pid {pid}).")
    return 0


def _stack_status(*, pidfile_path: str, socket_path: str) -> int:
    """
    Report whether the daemon is running and, when its control socket is
    reachable, a summary of the stack's interface addressing state plus the
    route and socket counts. Exits 0 when the daemon is running, 3 (the LSB
    "program is not running" convention) when it is not.
    """

    pid = _read_pidfile(pidfile_path)
    if pid is None:
        print("PyTCP stack is not running (no pidfile).")
        return 3
    if not _process_alive(pid):
        print(f"PyTCP stack is not running (stale pidfile, pid {pid}).")
        return 3

    print(f"PyTCP stack is running (pid {pid}).")
    print(f"  Control socket: {socket_path}")

    try:
        client = connect(socket_path=socket_path)
    except OSError as error:
        print(f"  Control socket unreachable: {error}")
        return 0

    # The stack summary is best-effort: a daemon running an older build may
    # not expose every control op (e.g. 'list_sockets'), so each section
    # degrades to a note rather than aborting the whole status report.
    try:
        try:
            views = _interface_views(client)
            if views:
                print()
                print(format_addr(views))
        except IpcRemoteError as error:
            print(f"  Interface summary unavailable: {error}")

        try:
            activity_text = format_activity(client.activity.list_activity())
            if activity_text:
                print()
                print(activity_text)
        except IpcRemoteError as error:
            print(f"  Activity summary unavailable: {error}")

        try:
            routes = client.route.list_routes()
            sockets = client.ss.list_sockets(family=None, socket_type=None, listening_only=False)
            print()
            print(f"Routes: {len(routes)}   Sockets: {len(sockets)}")
        except IpcRemoteError as error:
            print(f"  Route / socket summary unavailable: {error}")
    finally:
        client.close()
    return 0


def _cmd_stack_start(args: argparse.Namespace, /) -> int:
    """
    Run the 'stack start' command — launch the stack daemon in the
    foreground.
    """

    run_daemon(
        socket_path=args.ipc_socket,
        interfaces=args.interface or ["tap7"],
        pidfile_path=args.pidfile,
        on_ready=lambda path: print(f"PyTCP stack listening on {path}", flush=True),
    )
    return 0


def _cmd_stack_stop(args: argparse.Namespace, /) -> int:
    """
    Run the 'stack stop' command — signal the daemon via its pidfile.
    """

    return _stop_stack(args.pidfile)


def _cmd_stack_status(args: argparse.Namespace, /) -> int:
    """
    Run the 'stack status' command — report whether the daemon runs.
    """

    return _stack_status(pidfile_path=args.pidfile, socket_path=args.ipc_socket)


def _run_with_client(args: argparse.Namespace, /) -> int:
    """
    Connect to the daemon, run the selected 'args.func' handler against
    the live 'ClientStack', and print its rendered output. Reports an
    unreachable daemon cleanly (exit 1) rather than letting the connect
    traceback escape.
    """

    try:
        client = connect(socket_path=args.ipc_socket)
    except OSError as error:
        reason = error.strerror or str(error)
        print(
            f"pytcp: cannot reach the PyTCP stack daemon at {args.ipc_socket!r}: {reason}. "
            f"Is it running? Start it with 'pytcp stack start'.",
            file=sys.stderr,
        )
        return 1

    try:
        output = args.func(client, args)
    except IpcRemoteError as error:
        # A control op the daemon rejected (bad argument, unmet
        # precondition, etc.) — report it cleanly instead of letting the
        # remote-error traceback escape.
        print(f"pytcp: {error}", file=sys.stderr)
        return 1
    finally:
        client.close()

    if output:
        # Set the output off with a blank line before and after.
        print(f"\n{output}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """
    Parse the command line and run the selected subcommand. Each leaf
    subparser binds its handler via 'set_defaults(func=...)'; commands
    that talk to the daemon carry 'needs_client=True' and run through
    '_run_with_client', the rest ('stack' lifecycle) call their handler
    directly.
    """

    args = build_parser().parse_args(argv)

    if args.needs_client:
        return _run_with_client(args)
    return cast(int, args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
