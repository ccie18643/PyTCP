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
This module contains the PyTCP daemon run loop.

'run_daemon' boots the in-process stack (init -> add one interface ->
start), brings up the AF_UNIX control server so out-of-process
'pytcp.client' consumers can open sockets and drive the control APIs, and
then blocks until SIGINT / SIGTERM, tearing the IPC server and the stack
back down on the way out. 'default_socket_path' is the canonical control
socket location ('$XDG_RUNTIME_DIR/pytcp.sock', falling back to the
system temp dir). Readiness is reported through an 'on_ready' callback so
the run loop stays output-free and testable; the '__main__' CLI prints it.

pytcp/daemon/daemon.py

ver 3.0.8
"""

import os
import signal
import tempfile
import threading
from collections.abc import Callable
from typing import Any

from net_addr import Ip4IfAddr, Ip6IfAddr, MacAddress
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer

IPC__DAEMON__SOCKET_NAME: str = "pytcp.sock"
IPC__DAEMON__PIDFILE_NAME: str = "pytcp.pid"


def default_socket_path() -> str:
    """
    Return the canonical daemon control-socket path —
    '$XDG_RUNTIME_DIR/pytcp.sock' when the runtime dir is set, else the
    system temp dir (Linux 'ip'-tooling convention for a per-user runtime
    control endpoint).
    """

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    base = runtime_dir if runtime_dir else tempfile.gettempdir()
    return os.path.join(base, IPC__DAEMON__SOCKET_NAME)


def default_pidfile_path() -> str:
    """
    Return the canonical daemon pidfile path — '$XDG_RUNTIME_DIR/pytcp.pid'
    when the runtime dir is set, else the system temp dir.
    """

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    base = runtime_dir if runtime_dir else tempfile.gettempdir()
    return os.path.join(base, IPC__DAEMON__PIDFILE_NAME)


def _write_pidfile(pidfile_path: str, /) -> None:
    """
    Write the current process id to the pidfile.
    """

    with open(pidfile_path, "w", encoding="ascii") as handle:
        handle.write(f"{os.getpid()}\n")


def remove_pidfile(pidfile_path: str, /) -> None:
    """
    Remove the pidfile, tolerating its absence.
    """

    try:
        os.unlink(pidfile_path)
    except FileNotFoundError:
        pass


def _resolve_interface(interface_name: str, *, mac_address: MacAddress | None) -> dict[str, Any]:
    """
    Resolve the 'add_interface' kwargs for one interface name, dispatching
    on the 'tap' / 'tun' prefix.
    """

    match interface_name[:3]:
        case "tap":
            return stack.initialize_interface__tap(interface_name=interface_name, mac_address=mac_address)
        case "tun":
            return stack.initialize_interface__tun(interface_name=interface_name)

    raise ValueError(f"Unsupported interface type {interface_name[:3]!r}; only 'tap' and 'tun' are supported.")


def run_daemon(
    *,
    socket_path: str,
    interface_name: str = "tap7",
    mac_address: MacAddress | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4IfAddr | None = None,
    ip6_support: bool = True,
    ip6_host: Ip6IfAddr | None = None,
    on_ready: Callable[[str], None] | None = None,
    pidfile_path: str | None = None,
) -> None:
    """
    Run the PyTCP daemon: boot the stack on one interface, serve the
    AF_UNIX control socket, and block until SIGINT / SIGTERM.

    With no explicit host address a NIC autoconfigures (DHCPv4 for IPv4,
    SLAAC for IPv6). 'on_ready', if given, is called with 'socket_path'
    once the control server is listening. When 'pidfile_path' is given the
    process id is written there for the lifetime of the daemon (removed on
    exit) so 'pytcp daemon stop' can signal it.
    """

    stop = threading.Event()

    def _on_signal(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    # Write the pidfile up front — before 'stack.start()', which blocks
    # for up to DHCP4__BOOT_WAIT_MS (30 s) waiting for the DHCPv4 lease —
    # so 'pytcp daemon stop' can signal the process the instant it exists,
    # not only once autoconfiguration finishes. Removed in the finally.
    if pidfile_path is not None:
        _write_pidfile(pidfile_path)

    server: IpcServer | None = None
    stack_started = False
    try:
        stack.init()
        interface_args = _resolve_interface(interface_name, mac_address=mac_address)
        stack.add_interface(
            **interface_args,
            ip4_support=ip4_support,
            ip4_host=ip4_host,
            ip4_dhcp=ip4_support and ip4_host is None,
            ip6_support=ip6_support,
            ip6_host=ip6_host,
            ip6_gua_autoconfig=ip6_support and ip6_host is None,
        )
        # Do not block the daemon's bring-up on the DHCPv4 lease: start the
        # lifecycle and let the lease land in the background so the control
        # socket is reachable immediately (clients poll the address state).
        stack.start(wait_for_dhcp_bind=False)
        stack_started = True

        server = IpcServer(socket_path=socket_path)
        server.start()

        if on_ready is not None:
            on_ready(socket_path)

        stop.wait()
    finally:
        if server is not None:
            server.stop()
        if stack_started:
            stack.stop()
        if pidfile_path is not None:
            remove_pidfile(pidfile_path)
