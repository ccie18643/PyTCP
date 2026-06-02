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

'pytcp' is the operator front-end to a running PyTCP daemon, mirroring the
Linux network tools: 'pytcp ss' (sockets), 'pytcp route' (routing table),
'pytcp sysctl' (tunables), and 'pytcp daemon start' (run the daemon). The
observation subcommands open a short-lived control connection, call the
matching 'ClientStack' API, and render the result through the pure
formatters in 'cli__format'.

pytcp/cli/__main__.py

ver 3.0.8
"""

import argparse
import os
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass

from net_addr import Ip4Address, Ip4Mask, Ip4Network, Ip6Address, Ip6Network, NetAddrError
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


@dataclass(frozen=True, kw_only=True, slots=True)
class _RouteSpec:
    """
    A parsed net-tools 'route add' / 'route del' specification.
    """

    target: str | None
    netmask: str | None
    gateway: str | None
    dev: str | None
    metric: int
    is_host: bool
    is_default: bool


def _parse_route_spec(tokens: list[str], /) -> _RouteSpec:
    """
    Parse the net-tools 'route add' / 'route del' argument grammar into a
    '_RouteSpec' — the 'default' keyword, the '-net' / '-host' TARGET (or
    a bare TARGET), and the 'netmask' / 'gw' / 'dev' / 'metric'
    keyword-and-value tokens.
    """

    target = netmask = gateway = dev = None
    metric = 0
    is_host = is_default = False

    def _value(next_index: int, keyword: str) -> str:
        if next_index >= len(tokens):
            raise SystemExit(f"pytcp route: {keyword!r} requires a value.")
        return tokens[next_index]

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "default":
            is_default = True
        elif token in ("-net", "-host"):
            index += 1
            target = _value(index, token)
            is_host = token == "-host"
        elif token == "netmask":
            index += 1
            netmask = _value(index, "netmask")
        elif token == "gw":
            index += 1
            gateway = _value(index, "gw")
        elif token == "dev":
            index += 1
            dev = _value(index, "dev")
        elif token == "metric":
            index += 1
            try:
                metric = int(_value(index, "metric"))
            except ValueError:
                raise SystemExit("pytcp route: 'metric' must be an integer.") from None
        elif not token.startswith("-"):
            target = token
        else:
            raise SystemExit(f"pytcp route: unrecognized token {token!r}.")
        index += 1

    return _RouteSpec(
        target=target,
        netmask=netmask,
        gateway=gateway,
        dev=dev,
        metric=metric,
        is_host=is_host,
        is_default=is_default,
    )


def _route_dev_oif(client: ClientStack, dev: str | None, /) -> int | None:
    """
    Resolve a 'dev' interface name to its index for a route's egress
    interface, or 'None' when no 'dev' was given. Errors on an unknown
    interface name.
    """

    if dev is None:
        return None
    for ifindex in client.link.list_interfaces():
        if (client.link.interface(ifindex).name or f"if{ifindex}") == dev:
            return ifindex
    raise SystemExit(f"pytcp route: unknown interface {dev!r}.")


def _route_ip4_destination(spec: _RouteSpec, /) -> Ip4Network:
    """
    Build the IPv4 destination network from a '_RouteSpec' target — a
    CIDR target, an explicit '-host', or a target paired with a 'netmask'.
    """

    if spec.target is None:
        raise SystemExit("pytcp route: a target network or '-host' is required.")
    if "/" in spec.target:
        return Ip4Network(spec.target)
    if spec.is_host:
        return Ip4Network(f"{spec.target}/32")
    if spec.netmask is not None:
        return Ip4Network((Ip4Address(spec.target), Ip4Mask(spec.netmask)))
    raise SystemExit("pytcp route: an IPv4 route needs a 'netmask', a '/prefix', or '-host'.")


def _route_ip6_destination(spec: _RouteSpec, /) -> Ip6Network:
    """
    Build the IPv6 destination prefix from a '_RouteSpec' target — a
    '/prefix' target or an explicit '-host'.
    """

    if spec.target is None:
        raise SystemExit("pytcp route: a target prefix or '-host' is required.")
    if spec.is_host:
        return Ip6Network(f"{spec.target.split('/')[0]}/128")
    if "/" in spec.target:
        return Ip6Network(spec.target)
    raise SystemExit("pytcp route: an IPv6 route needs a '/prefix' (or '-host').")


def _route_modify_ip4(client: ClientStack, *, verb: str, spec: _RouteSpec, oif: int | None) -> None:
    """
    Apply an IPv4 'route add' / 'route del' against the daemon's FIB.
    """

    gateway = Ip4Address(spec.gateway) if spec.gateway is not None else None
    if verb == "del":
        if spec.is_default:
            client.route.remove_default(family=AddressFamily.INET4)
        else:
            client.route.remove_route(destination=_route_ip4_destination(spec), gateway=gateway)
        return
    if spec.is_default:
        if gateway is None:
            raise SystemExit("pytcp route: 'add default' requires 'gw'.")
        client.route.replace_default(gateway=gateway, protocol=RouteProtocol.STATIC, oif=oif)
        return
    scope = RouteScope.UNIVERSE if gateway is not None else RouteScope.LINK
    client.route.add_route(
        route=Route(
            destination=_route_ip4_destination(spec),
            gateway=gateway,
            oif=oif,
            metric=spec.metric,
            scope=scope,
            protocol=RouteProtocol.STATIC,
        )
    )


def _route_modify_ip6(client: ClientStack, *, verb: str, spec: _RouteSpec, oif: int | None) -> None:
    """
    Apply an IPv6 'route add' / 'route del' against the daemon's FIB.
    """

    gateway = Ip6Address(spec.gateway) if spec.gateway is not None else None
    if verb == "del":
        if spec.is_default:
            client.route.remove_default(family=AddressFamily.INET6)
        else:
            client.route.remove_route(destination=_route_ip6_destination(spec), gateway=gateway)
        return
    if spec.is_default:
        if gateway is None:
            raise SystemExit("pytcp route: 'add default' requires 'gw'.")
        client.route.replace_default(gateway=gateway, protocol=RouteProtocol.STATIC, oif=oif)
        return
    scope = RouteScope.UNIVERSE if gateway is not None else RouteScope.LINK
    client.route.add_route(
        route=Route(
            destination=_route_ip6_destination(spec),
            gateway=gateway,
            oif=oif,
            metric=spec.metric,
            scope=scope,
            protocol=RouteProtocol.STATIC,
        )
    )


def _cmd_route_modify(client: ClientStack, *, verb: str, tokens: list[str], family: AddressFamily) -> str:
    """
    Run a 'route add' / 'route del' against the daemon's FIB. Returns an
    empty string — net-tools 'route' prints nothing on a successful
    modification.
    """

    spec = _parse_route_spec(tokens)
    oif = _route_dev_oif(client, spec.dev)
    try:
        if family is AddressFamily.INET6:
            _route_modify_ip6(client, verb=verb, spec=spec, oif=oif)
        else:
            _route_modify_ip4(client, verb=verb, spec=spec, oif=oif)
    except NetAddrError as error:
        raise SystemExit(f"pytcp route: {error}") from error
    return ""


def _cmd_route(client: ClientStack, args: argparse.Namespace, /) -> str:
    """
    Render the routing table for the 'route' subcommand. Mirrors
    net-tools 'route': IPv4 by default, IPv6 with '-6' / '-A inet6';
    'route add' / 'route del' modify the daemon's FIB.
    """

    if args.inet6 or args.family == "inet6":
        family = AddressFamily.INET6
    else:
        family = AddressFamily.INET4
    if args.spec:
        verb, *tokens = args.spec
        if verb not in ("add", "del"):
            raise SystemExit(f"pytcp route: unknown command {verb!r} (expected 'add' or 'del').")
        return _cmd_route_modify(client, verb=verb, tokens=tokens, family=family)
    if args.cache:
        # net-tools 'route -C' shows the routing cache, not the FIB; PyTCP
        # keeps no cache, so this is the empty-cache header (like Linux).
        return format_route_cache(family=family)
    return format_route_table(
        client.route.list_routes(family=family),
        family=family,
        numeric=args.numeric,
        interface_names=_interface_names(client),
    )


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


_COMMANDS: dict[str, Callable[[ClientStack, argparse.Namespace], str]] = {
    "ss": _cmd_ss,
    "route": _cmd_route,
    "sysctl": _cmd_sysctl,
    "neigh": _cmd_neigh,
    "addr": _cmd_addr,
    "link": _cmd_link,
}


def build_parser() -> argparse.ArgumentParser:
    """
    Build the 'pytcp' multitool argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="pytcp",
        description="Operator front-end to a running PyTCP daemon.",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--ipc-socket",
        default=default_socket_path(),
        help="AF_UNIX control-socket path (default: $XDG_RUNTIME_DIR/pytcp.sock).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_ss = subparsers.add_parser("ss", parents=[common], help="Show socket statistics.")
    parser_ss.add_argument("-t", "--tcp", action="store_true", help="Show only TCP sockets.")
    parser_ss.add_argument("-u", "--udp", action="store_true", help="Show only UDP sockets.")
    parser_ss.add_argument("-l", "--listening", action="store_true", help="Show only listening sockets.")
    parser_ss.add_argument("-4", "--ipv4", action="store_true", help="Show only IPv4 sockets.")
    parser_ss.add_argument("-6", "--ipv6", action="store_true", help="Show only IPv6 sockets.")

    parser_route = subparsers.add_parser("route", parents=[common], help="Show the routing table (net-tools 'route').")
    parser_route.add_argument(
        "-n",
        "--numeric",
        action="store_true",
        help="Show numeric addresses (render the default route's destination as 0.0.0.0).",
    )
    parser_route.add_argument(
        "-e",
        "--extend",
        action="count",
        default=0,
        help="Display more information (accepted for net-tools compatibility).",
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
        "-F",
        "--fib",
        action="store_true",
        help="Display the Forwarding Information Base (the default; accepted for net-tools compatibility).",
    )
    parser_route.add_argument(
        "-C",
        "--cache",
        action="store_true",
        help="Display the routing cache (accepted for net-tools compatibility; PyTCP keeps no route cache).",
    )
    parser_route.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Be verbose (accepted for net-tools compatibility).",
    )
    parser_route.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pytcp route (PyTCP {__version__})",
    )
    parser_route.add_argument(
        "spec",
        nargs=argparse.REMAINDER,
        help="'add' / 'del' plus a net-tools route spec "
        "(e.g. 'add -net 10.9.0.0/24 gw 10.0.1.254 dev tap7', 'del default').",
    )
    subparsers.add_parser("neigh", parents=[common], help="Show the neighbour caches.")
    subparsers.add_parser("addr", parents=[common], help="Show interfaces with their addresses.")
    subparsers.add_parser("link", parents=[common], help="Show interfaces.")

    parser_sysctl = subparsers.add_parser("sysctl", parents=[common], help="Read or write sysctl values.")
    parser_sysctl.add_argument(
        "key",
        nargs="?",
        default=None,
        help="A sysctl key to read, 'key=value' to set, or omit to list all.",
    )

    parser_daemon = subparsers.add_parser("daemon", help="Manage the PyTCP daemon.")
    daemon_subparsers = parser_daemon.add_subparsers(dest="daemon_command", required=True)
    parser_start = daemon_subparsers.add_parser("start", help="Start the daemon in the foreground.")
    parser_start.add_argument("--ipc-socket", default=default_socket_path(), help="AF_UNIX control-socket path.")
    parser_start.add_argument(
        "-i",
        "--interface",
        action="append",
        metavar="INTERFACE",
        help="TAP/TUN interface to bind to; repeat for a multi-homed host (default: tap7).",
    )
    parser_start.add_argument("--pidfile", default=default_pidfile_path(), help="Pidfile path for 'daemon stop'.")
    parser_stop = daemon_subparsers.add_parser("stop", help="Stop the daemon via its pidfile.")
    parser_stop.add_argument("--pidfile", default=default_pidfile_path(), help="Pidfile path to signal.")

    parser_status = daemon_subparsers.add_parser(
        "status",
        help="Show whether the daemon is running and the stack's state (exit 0 running, 3 not running).",
    )
    parser_status.add_argument("--ipc-socket", default=default_socket_path(), help="AF_UNIX control-socket path.")
    parser_status.add_argument("--pidfile", default=default_pidfile_path(), help="Pidfile path to read.")

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


def _stop_daemon(pidfile_path: str, /) -> int:
    """
    Signal a running daemon to stop via its pidfile, cleaning up a stale
    pidfile if the process is gone.
    """

    pid = _read_pidfile(pidfile_path)
    if pid is None:
        print("PyTCP daemon is not running (no pidfile).", file=sys.stderr)
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        remove_pidfile(pidfile_path)
        print(f"PyTCP daemon (pid {pid}) is not running; removed stale pidfile.", file=sys.stderr)
        return 1

    print(f"Sent SIGTERM to PyTCP daemon (pid {pid}).")
    return 0


def _daemon_status(*, pidfile_path: str, socket_path: str) -> int:
    """
    Report whether the daemon is running and, when its control socket is
    reachable, a summary of the stack's interface addressing state plus the
    route and socket counts. Exits 0 when the daemon is running, 3 (the LSB
    "program is not running" convention) when it is not.
    """

    pid = _read_pidfile(pidfile_path)
    if pid is None:
        print("PyTCP daemon is not running (no pidfile).")
        return 3
    if not _process_alive(pid):
        print(f"PyTCP daemon is not running (stale pidfile, pid {pid}).")
        return 3

    print(f"PyTCP daemon is running (pid {pid}).")
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


def _run_daemon_command(args: argparse.Namespace, /) -> int:
    """
    Dispatch the 'daemon' subcommand.
    """

    if args.daemon_command == "start":
        run_daemon(
            socket_path=args.ipc_socket,
            interfaces=args.interface or ["tap7"],
            pidfile_path=args.pidfile,
            on_ready=lambda path: print(f"PyTCP daemon listening on {path}", flush=True),
        )
        return 0

    if args.daemon_command == "stop":
        return _stop_daemon(args.pidfile)

    if args.daemon_command == "status":
        return _daemon_status(pidfile_path=args.pidfile, socket_path=args.ipc_socket)

    raise AssertionError(f"Unhandled daemon command {args.daemon_command!r}.")


def main(argv: list[str] | None = None) -> int:
    """
    Parse the command line and run the requested subcommand.
    """

    args = build_parser().parse_args(argv)

    if args.command == "daemon":
        return _run_daemon_command(args)

    try:
        client = connect(socket_path=args.ipc_socket)
    except OSError as error:
        # The daemon is not up yet (socket missing) or not accepting
        # connections (refused) — report it cleanly instead of letting
        # the connect traceback escape to the operator.
        reason = error.strerror or str(error)
        print(
            f"pytcp: cannot reach the PyTCP daemon at {args.ipc_socket!r}: {reason}. "
            f"Is the daemon running? Start it with 'pytcp daemon start'.",
            file=sys.stderr,
        )
        return 1

    try:
        output = _COMMANDS[args.command](client, args)
    finally:
        client.close()

    if output:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
