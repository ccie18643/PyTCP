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
(tunables), 'pytcp addr' / 'link' / 'neigh', and 'pytcp stack start' (run
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
from typing import Any, cast, override

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network, NetAddrError
from pytcp import __version__
from pytcp.cli.cli__format import (
    InterfaceView,
    format_activity,
    format_addr,
    format_link,
    format_neighbor_table,
    format_route_cache,
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
from pytcp.stack.neighbor import NeighborSnapshot


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
    Render the socket table for the 'ss' subcommand.
    """

    socket_type: SocketType | None = None
    if args.tcp and not args.udp:
        socket_type = SocketType.STREAM
    elif args.udp and not args.tcp:
        socket_type = SocketType.DGRAM

    family: AddressFamily | None = None
    if args.ipv4 and not args.ipv6:
        family = AddressFamily.INET4
    elif args.ipv6 and not args.ipv4:
        family = AddressFamily.INET6

    return format_socket_table(
        client.ss.list_sockets(family=family, socket_type=socket_type, listening_only=args.listening)
    )


def _interface_names(client: ClientStack, /) -> dict[int, str]:
    """
    Map each interface's ifindex to its name for the 'dev' column.
    """

    return {
        ifindex: (client.link.interface(ifindex).name or f"if{ifindex}") for ifindex in client.link.list_interfaces()
    }


def _route_dev_oif(client: ClientStack, dev: str | None, /) -> int | None:
    """
    Resolve a '--dev' interface name to its index for a route's egress
    interface, or 'None' when no '--dev' was given. Errors on an unknown
    interface name.
    """

    if dev is None:
        return None
    for ifindex in client.link.list_interfaces():
        if (client.link.interface(ifindex).name or f"if{ifindex}") == dev:
            return ifindex
    raise SystemExit(f"pytcp route: unknown interface {dev!r}.")


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
    return bool(args.inet6) or args.family == "inet6"


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


def _cmd_route_list(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render the routing table for a bare 'route' (no add / del). With no
    family flag both the IPv4 and IPv6 tables are shown; '-4' / '-6' /
    '-A' narrow to one. '-C' shows the empty routing cache instead of the
    FIB.
    """

    families: tuple[AddressFamily, ...]
    if args.inet6 or args.family == "inet6":
        families = (AddressFamily.INET6,)
    elif args.inet or args.family == "inet":
        families = (AddressFamily.INET4,)
    else:
        families = (AddressFamily.INET4, AddressFamily.INET6)

    # net-tools 'route -C' shows the routing cache, not the FIB; PyTCP
    # keeps no cache, so the cache body is just the (empty) column header.
    names: dict[int, str] = {} if args.cache else _interface_names(client)
    sections = [_hl("PyTCP Routing Cache" if args.cache else "PyTCP Routing Table")]
    for family in families:
        label = "IPv4" if family is AddressFamily.INET4 else "IPv6"
        if args.cache:
            body = format_route_cache(family=family)
        else:
            body = format_route_table(
                client.route.list_routes(family=family),
                family=family,
                numeric=args.numeric,
                interface_names=names,
            )
        # The body is 'column-header\n<rows>'; highlight the label and the
        # column header, leave the rows in the terminal default colour.
        column_header, _, rows = body.partition("\n")
        section = f"{_hl(label)}\n{_hl(column_header)}"
        sections.append(f"{section}\n{rows}" if rows else section)

    return "\n\n".join(sections)


def _cmd_sysctl(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Read or write a sysctl value, or list all, for the 'sysctl' subcommand.
    """

    if args.key is None:
        return format_sysctl(client.sysctl.snapshot())
    if "=" in args.key:
        key, _, value = args.key.partition("=")
        client.sysctl.set(key, _parse_sysctl_value(value))
        return ""
    return f"{args.key} = {client.sysctl.get(args.key)}"


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


def _cmd_neigh(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render the neighbour caches across interfaces for the 'neigh' subcommand.
    """

    _ = args
    snapshots: list[NeighborSnapshot] = []
    for ifindex in client.link.list_interfaces():
        snapshots.extend(client.neighbor.interface(ifindex).list_neighbors())
    return format_neighbor_table(snapshots)


def _cmd_addr(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render interfaces with their addresses for the 'addr' subcommand.
    """

    _ = args
    return format_addr(_interface_views(client))


def _cmd_link(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render interfaces without addresses for the 'link' subcommand.
    """

    _ = args
    return format_link(_interface_views(client))


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

    # Observation commands talk to the daemon and so run through the
    # shared connect path; the 'stack' lifecycle commands override this.
    parser.set_defaults(needs_client=True)

    subparsers = parser.add_subparsers(dest="command", required=True, title="commands", metavar="<command>")

    parser_ss = subparsers.add_parser("ss", help="Show socket statistics.")
    parser_ss.add_argument("-t", "--tcp", action="store_true", help="Show only TCP sockets.")
    parser_ss.add_argument("-u", "--udp", action="store_true", help="Show only UDP sockets.")
    parser_ss.add_argument("-l", "--listening", action="store_true", help="Show only listening sockets.")
    parser_ss.add_argument("-4", "--ipv4", action="store_true", help="Show only IPv4 sockets.")
    parser_ss.add_argument("-6", "--ipv6", action="store_true", help="Show only IPv6 sockets.")
    parser_ss.set_defaults(func=_cmd_ss)

    parser_route = subparsers.add_parser("route", help="Show or modify the routing table.")
    parser_route.add_argument(
        "-n",
        "--numeric",
        action="store_true",
        help="Show numeric addresses (render the default route's destination as 0.0.0.0).",
    )
    parser_route.add_argument("-4", dest="inet", action="store_true", help="Show the IPv4 routing table (default).")
    parser_route.add_argument("-6", dest="inet6", action="store_true", help="Show the IPv6 routing table.")
    parser_route.add_argument(
        "-A",
        dest="family",
        choices=("inet", "inet6"),
        help="Address family to display (inet | inet6).",
    )
    parser_route.add_argument(
        "-C",
        "--cache",
        action="store_true",
        help="Show the routing cache (empty; PyTCP keeps no route cache).",
    )
    parser_route.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pytcp route (PyTCP {__version__})",
    )
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

    parser_neigh = subparsers.add_parser("neigh", help="Show the neighbour caches.")
    parser_neigh.set_defaults(func=_cmd_neigh)
    parser_addr = subparsers.add_parser("addr", help="Show interfaces with their addresses.")
    parser_addr.set_defaults(func=_cmd_addr)
    parser_link = subparsers.add_parser("link", help="Show interfaces.")
    parser_link.set_defaults(func=_cmd_link)

    parser_sysctl = subparsers.add_parser("sysctl", help="Read or write sysctl values.")
    parser_sysctl.add_argument(
        "key",
        nargs="?",
        default=None,
        help="A sysctl key to read, 'key=value' to set, or omit to list all.",
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
