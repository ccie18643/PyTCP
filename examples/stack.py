#!/usr/bin/env python3

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
This module contains code that runs the stack without any 'user space' services.
Stack should only respond to the ping packets. This example is also used as a
base to run other examples provided as the subsystems.

examples/stack.py

ver 3.0.8
"""

import signal
import time
from types import FrameType
from typing import Any

import click

from examples.lib.subsystem import Subsystem
from net_addr import (
    ClickTypeIp4Address,
    ClickTypeIp4IfAddr,
    ClickTypeIp6Address,
    ClickTypeIp6IfAddr,
    ClickTypeMacAddress,
    Ip4Address,
    Ip4IfAddr,
    Ip6Address,
    Ip6IfAddr,
    MacAddress,
)
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.stack import RouteProtocol


def _capture_stats_snapshot() -> dict[str, int]:
    """
    Snapshot the live packet-handler stats + ring qsize observables.
    Iterates the 'PacketStatsRx' / 'PacketStatsTx' dataclass fields
    generically so any new counter (including ring-level drops, now
    living on the same dataclass via the shared-stats refactor)
    appears in the output without a curated list.
    """

    import dataclasses

    # Iterate the per-ifindex interface registry (the successor to the
    # retired 'stack.packet_handler' / 'stack.{rx,tx}_ring' singletons).
    # Counters are summed across interfaces; ring qsizes are reported
    # per-ifindex live gauges.
    snap: dict[str, int] = {}
    for ifindex, handler in stack.interfaces.items():
        for prefix, stats in (
            ("rx", handler.packet_stats_rx),
            ("tx", handler.packet_stats_tx),
        ):
            for field in dataclasses.fields(stats):
                key = f"{prefix}__{field.name}"
                snap[key] = snap.get(key, 0) + getattr(stats, field.name)
        # qsize is a live gauge, not a counter — keep it explicit so
        # the renderer can show it even when delta is zero.
        if handler._rx_ring is not None:
            snap[f"if{ifindex}__rx_ring__qsize"] = handler._rx_ring.qsize
        if handler._tx_ring is not None:
            snap[f"if{ifindex}__tx_ring__qsize"] = handler._tx_ring.qsize
    return snap


def _print_stats_delta(prev: dict[str, int], now: dict[str, int], interval: int) -> None:
    """
    Pretty-print the per-counter delta + per-second rate over the
    'interval' window since the last snapshot.
    """

    print("=" * 70)
    print(f"PyTCP stats — {interval}s window")
    print("-" * 70)
    print(f"  {'counter':<40} {'total':>12} {'delta':>8} {'pps':>8}")
    for key in sorted(now):
        total = now[key]
        delta = total - prev.get(key, 0)
        pps = delta // interval if interval else 0
        if delta or "qsize" in key:
            print(f"  {key:<40} {total:>12} {delta:>8} {pps:>8}")
    print("=" * 70)


def _resolve_interface_args(
    ctx: click.Context,
    *,
    interface_name: str,
    mac_address: MacAddress | None,
    ip4_support: bool,
    ip4_host: Ip4IfAddr | None,
    ip6_support: bool,
    ip6_host: Ip6IfAddr | None,
) -> dict[str, Any]:
    """
    Resolve the low-level 'add_interface' kwargs for one interface name,
    dispatching on the 'tap' / 'tun' prefix. Exits with a diagnostic on
    an unsupported interface type, or on a TUN interface missing the
    host address its point-to-point link requires.
    """

    match interface_name[:3]:
        case "tap":
            return stack.initialize_interface__tap(interface_name=interface_name, mac_address=mac_address)
        case "tun":
            addressing_issue = False
            if ip4_support and not ip4_host:
                click.secho(
                    "IPv4 host address must be provided for TUN interface when IPv4 support is enabled.",
                    fg="red",
                )
                addressing_issue = True
            if ip6_support and not ip6_host:
                click.secho(
                    "IPv6 host address must be provided for TUN interface when IPv6 support is enabled.",
                    fg="red",
                )
                addressing_issue = True
            if addressing_issue:
                ctx.exit(1)
            return stack.initialize_interface__tun(interface_name=interface_name)
        case _:
            click.secho(
                f"Invalid interface type '{interface_name[:3]}'. Only 'tap' and 'tun' interfaces are supported.",
                fg="red",
            )
            ctx.exit(1)


@click.command()
@click.option(
    "--stack-interface",
    "stack__interface",
    multiple=True,
    help=(
        "Interface for the stack. Repeat to bind multiple interfaces "
        "(e.g. '--stack-interface tap7 --stack-interface tap9'). "
        "Defaults to 'tap7'. With more than one interface every NIC "
        "autoconfigures (DHCPv4 / SLAAC); the per-interface address / "
        "MAC / gateway options are single-interface only."
    ),
)
@click.option(
    "--stack-mac-address",
    "stack__mac_address",
    type=ClickTypeMacAddress(),
    default=None,
    help="MAC address to be assigned to the stack interface.",
)
@click.option(
    "--stack-no-ip6",
    "stack__ip6_support",
    is_flag=True,
    default=True,
    help="Do not enable stack IPv6 support.",
)
@click.option(
    "--stack-ip6-address",
    "stack__ip6_host",
    type=ClickTypeIp6IfAddr(),
    default=None,
    help="IPv6 address/mask to be assigned to the stack interface.",
)
@click.option(
    "--stack-ip6-gateway",
    "stack__ip6_gateway",
    type=ClickTypeIp6Address(),
    default=None,
    help="IPv6 gateway address to be assigned to the stack interface.",
)
@click.option(
    "--stack-no-ip4",
    "stack__ip4_support",
    is_flag=True,
    default=True,
    help="Do not enable stack IPv4 support.",
)
@click.option(
    "--stack-ip4-address",
    "stack__ip4_host",
    type=ClickTypeIp4IfAddr(),
    default=None,
    help="IPv4 address/mask to be assigned to the stack interface.",
)
@click.option(
    "--stack-ip4-gateway",
    "stack__ip4_gateway",
    type=ClickTypeIp4Address(),
    default=None,
    help="IPv4 gateway address to be assigned to the stack interface.",
)
@click.option(
    "--ipc-socket",
    "stack__ipc_socket",
    default=None,
    help=(
        "Run as a daemon: also listen on this AF_UNIX path so out-of-"
        "process clients can open sockets and drive the control APIs via "
        "'pytcp.client' (e.g. '--ipc-socket /tmp/pytcp.sock')."
    ),
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    stack__interface: tuple[str, ...],
    stack__mac_address: MacAddress | None,
    stack__ip6_support: bool,
    stack__ip6_host: Ip6IfAddr | None,
    stack__ip6_gateway: Ip6Address | None,
    stack__ip4_support: bool,
    stack__ip4_host: Ip4IfAddr | None,
    stack__ip4_gateway: Ip4Address | None,
    stack__ipc_socket: str | None = None,
    subsystems: list[Subsystem] | None = None,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C. Also
    run the provided subsystems if any.
    """

    # Default to the single 'tap7' interface when none is supplied, so
    # the bare 'make run' / subsystem examples behave exactly as before.
    interfaces = stack__interface or ("tap7",)
    multi = len(interfaces) > 1

    # The per-interface address / MAC / gateway options are scalar — they
    # cannot describe more than one NIC. With multiple interfaces every
    # NIC autoconfigures (DHCPv4 / SLAAC) instead.
    if multi:
        if any(
            opt is not None
            for opt in (
                stack__mac_address,
                stack__ip4_host,
                stack__ip4_gateway,
                stack__ip6_host,
                stack__ip6_gateway,
            )
        ):
            click.secho(
                "The --stack-mac-address / --stack-ip{4,6}-address / "
                "--stack-ip{4,6}-gateway options are single-interface only; "
                "multiple interfaces autoconfigure (DHCPv4 / SLAAC).",
                fg="red",
            )
            ctx.exit(1)
        if any(name[:3] != "tap" for name in interfaces):
            click.secho(
                "Multiple interfaces are supported for 'tap' only " "(TUN requires explicit per-interface addressing).",
                fg="red",
            )
            ctx.exit(1)

    if subsystems is None:
        subsystems = []

    # Daemon-shaped boot: bring the stack core up with no interface,
    # then attach the operator's interface(s) as runtime devices. This is
    # the 'ip link add' / RTM_NEWLINK flow — 'init()' is the kernel boot,
    # 'add_interface()' registers each NIC, 'start()' brings them up.
    stack.init()

    # Track the ifindex each 'add_interface' (RTM_NEWLINK) allocates so a
    # runtime 'remove_interface' (RTM_DELLINK, on SIGUSR1 below) can tear
    # the most-recently-added one down live.
    added_ifindexes: list[int] = []

    for interface_name in interfaces:
        # Scalar addressing applies only in single-interface mode; with
        # multiple interfaces each NIC autoconfigures (host left None).
        ip4_host = stack__ip4_host if not multi else None
        ip6_host = stack__ip6_host if not multi else None
        interface_args = _resolve_interface_args(
            ctx,
            interface_name=interface_name,
            mac_address=stack__mac_address if not multi else None,
            ip4_support=stack__ip4_support,
            ip4_host=ip4_host,
            ip6_support=stack__ip6_support,
            ip6_host=ip6_host,
        )
        # No static IPv4 address means autoconfigure via DHCPv4.
        ip4_dhcp = stack__ip4_support and ip4_host is None
        # No static IPv6 address means SLAAC (GUA) autoconfiguration.
        ip6_gua_autoconfig = stack__ip6_support and ip6_host is None
        added_ifindexes.append(
            stack.add_interface(
                **interface_args,
                ip6_support=stack__ip6_support,
                ip6_host=ip6_host,
                ip6_gua_autoconfig=ip6_gua_autoconfig,
                ip4_support=stack__ip4_support,
                ip4_host=ip4_host,
                ip4_dhcp=ip4_dhcp,
            )
        )

    # The next hop is FIB state, not a per-IfAddr attribute. Install the
    # operator-supplied default gateway through the Route API (the FIBs
    # were built by 'init()'). Gateways are scalar, hence single-interface
    # only; multi-interface mode learns the default route via RA / DHCP.
    if not multi:
        if stack__ip6_support and stack__ip6_gateway is not None:
            stack.route.replace_default(gateway=stack__ip6_gateway, protocol=RouteProtocol.BOOT)
        if stack__ip4_support and stack__ip4_gateway is not None:
            stack.route.replace_default(gateway=stack__ip4_gateway, protocol=RouteProtocol.BOOT)

    ipc_server: IpcServer | None = None

    try:
        stack.start()

        # Daemon mode: expose the AF_UNIX control socket so out-of-process
        # 'pytcp.client' consumers can open sockets / drive the control
        # APIs against this running stack. The socket syscalls and the
        # six control APIs are served once the stack singletons are up.
        if stack__ipc_socket is not None:
            ipc_server = IpcServer(socket_path=stack__ipc_socket)
            ipc_server.start()
            click.echo(f"IPC: listening on {stack__ipc_socket} (out-of-process clients via pytcp.client)")

        for subsystem in subsystems:
            if stack__ip6_support:
                subsystem.stack_ip6_address = stack__ip6_host.address if stack__ip6_host else Ip6Address()
            if stack__ip4_support:
                subsystem.stack_ip4_address = stack__ip4_host.address if stack__ip4_host else Ip4Address()
            subsystem.start()

        # Runtime interface removal (RTM_DELLINK) over the daemon's
        # "control channel": SIGUSR1 tears down the most-recently-added
        # interface on the live stack. The handler only sets a flag (the
        # async-signal-safe minimum); the run loop below does the actual
        # 'remove_interface', which runs the teardown cascade (abort bound
        # sessions, drop addresses, flush neighbour caches, purge egress
        # routes, stop the interface threads). Try it with:
        #   kill -USR1 $(pgrep -f 'examples/stack.py')
        _remove_requested = [False]

        def _on_sigusr1(_signum: int, _frame: FrameType | None) -> None:
            _remove_requested[0] = True

        signal.signal(signal.SIGUSR1, _on_sigusr1)

        # Periodic stats snapshot — disabled by default; opt-in for
        # flood-testing / benchmarking by setting the
        # 'PYTCP_STATS_INTERVAL' env var to a positive integer
        # (seconds between snapshots). 'make benchmark' does this
        # automatically; casual 'make run' stays quiet.
        import os as _os

        _stats_interval = int(_os.environ.get("PYTCP_STATS_INTERVAL", "0"))
        _last_stats = time.monotonic()
        _last_snapshot = _capture_stats_snapshot()

        while any(subsystem.is_alive for subsystem in subsystems if subsystem) or not subsystems:
            time.sleep(1)
            if _remove_requested[0]:
                _remove_requested[0] = False
                if added_ifindexes:
                    ifindex = added_ifindexes.pop()
                    stack.remove_interface(ifindex)
                    click.echo(f"SIGUSR1: removed interface ifindex={ifindex} (RTM_DELLINK)")
                else:
                    click.echo("SIGUSR1: no runtime-added interface left to remove")
            if _stats_interval and time.monotonic() - _last_stats >= _stats_interval:
                now_snapshot = _capture_stats_snapshot()
                _print_stats_delta(_last_snapshot, now_snapshot, _stats_interval)
                _last_snapshot = now_snapshot
                _last_stats = time.monotonic()

    except KeyboardInterrupt:
        pass

    finally:
        for subsystem in subsystems:
            if subsystem.is_alive:
                subsystem.stop()
        if ipc_server is not None:
            ipc_server.stop()
        stack.stop()


if __name__ == "__main__":
    cli.main()
