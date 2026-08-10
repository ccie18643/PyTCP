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

ver 3.0.10
"""

import os
import signal
import sys
import tempfile
import threading
from collections.abc import Callable
from typing import Any, BinaryIO

from net_addr import Ip4IfAddr, Ip6IfAddr, MacAddress
from pytcp import stack
from pytcp.daemon.daemon__capture import DaemonCapture
from pytcp.ipc.ipc__server import IpcServer
from pytcp.lib.logger import log
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket import socket as pytcp_socket
from pytcp.runtime.socket.packet__socket import PacketSocket

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


def _start_capture(capture_path: str, /, *, pcap: bool) -> tuple[DaemonCapture, PacketSocket, BinaryIO | None]:
    """
    Open the capture sink ('-' = stdout, else a file), bind an internal
    capture-all AF_PACKET socket, and start the drain writer. 'pcap'
    selects a libpcap-stream sink (for 'tshark -r') over the default
    decoded-text sink. Return the writer, the socket, and the file to
    close on teardown ('None' for stdout). Called after 'stack.init()' and
    before 'stack.start()' so the writer sees the stack's boot from frame
    one.
    """

    sink: BinaryIO
    owned_file: BinaryIO | None
    if capture_path == "-":
        sink = sys.stdout.buffer
        owned_file = None
    else:
        sink = open(capture_path, "wb", buffering=0)  # noqa: SIM115
        owned_file = sink

    # Construct through the sanctioned socket factory (the user/kernel
    # transition), not by instantiating PacketSocket directly.
    capture_socket = pytcp_socket(family=AddressFamily.PACKET, type=SocketType.RAW)
    assert isinstance(capture_socket, PacketSocket)
    capture = DaemonCapture(capture_socket=capture_socket, sink=sink, pcap=pcap)
    capture.start()
    return capture, capture_socket, owned_file


def _stop_capture(capture: DaemonCapture, capture_socket: PacketSocket, owned_file: BinaryIO | None, /) -> None:
    """
    Stop the drain writer, close the capture socket, and close the sink
    file if the daemon opened one (never stdout).
    """

    capture.stop()
    capture_socket.close()
    if owned_file is not None:
        owned_file.close()


def run_daemon(
    *,
    socket_path: str,
    interfaces: list[str],
    mac_address: MacAddress | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4IfAddr | None = None,
    ip6_support: bool = True,
    ip6_host: Ip6IfAddr | None = None,
    on_ready: Callable[[str], None] | None = None,
    pidfile_path: str | None = None,
    capture_path: str | None = None,
    capture_pcap: bool = False,
) -> None:
    """
    Run the PyTCP daemon: boot the stack on one or more interfaces, serve
    the AF_UNIX control socket, and block until SIGINT / SIGTERM.

    With a single interface the explicit MAC / host-address arguments
    apply; each NIC otherwise autoconfigures (DHCPv4 for IPv4, SLAAC for
    IPv6). With several interfaces the per-interface static arguments are
    ignored — every NIC autoconfigures and a per-interface address is set
    at runtime through the Address API.

    'on_ready', if given, is called with 'socket_path' once the control
    server is listening. When 'pidfile_path' is given the process id is
    written there for the lifetime of the daemon (removed on exit) so
    'pytcp stack stop' can signal it.

    When 'capture_path' is given the daemon binds an internal AF_PACKET
    capture socket before the stack starts and writes captured frames to
    that file ('-' for stdout). Binding before 'stack.start()' captures
    the stack's own boot — IPv6 DAD / RS / RA, RFC 5227 ARP Probe /
    Announcement, DHCPv4 — which a client-attached 'pytcp tcpdump' cannot
    see. With 'capture_pcap' the file is a libpcap stream ('tshark -r'
    decodable); otherwise it is decoded, direction-tagged tcpdump-style
    text.
    """

    stop = threading.Event()

    def _on_signal(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    # Write the pidfile up front — before 'stack.start()', which blocks
    # for up to DHCP4__BOOT_WAIT_MS (30 s) waiting for the DHCPv4 lease —
    # so 'pytcp stack stop' can signal the process the instant it exists,
    # not only once autoconfiguration finishes. Removed in the finally.
    if pidfile_path is not None:
        _write_pidfile(pidfile_path)

    server: IpcServer | None = None
    stack_started = False
    capture_state: tuple[DaemonCapture, PacketSocket, BinaryIO | None] | None = None
    try:
        stack.init()
        # Per-interface static MAC / host arguments only apply to a
        # single-NIC daemon; with several interfaces every NIC
        # autoconfigures (a shared static address / MAC across NICs would
        # collide).
        single = len(interfaces) == 1
        for interface_name in interfaces:
            try:
                interface_args = _resolve_interface(interface_name, mac_address=mac_address if single else None)
            except OSError as error:
                # Opening the TAP/TUN device failed at the OS boundary
                # (EBUSY — another process holds it; ENODEV — it does not
                # exist; EPERM — needs elevated privileges). Report it as
                # one CRITICAL line and exit gracefully (non-zero) instead
                # of dumping a raw OSError traceback on the operator.
                detail = error.strerror or str(error)
                log(
                    "stack",
                    f"<CRIT>Cannot open interface {interface_name}: {detail} (errno {error.errno}). "
                    f"Another process may already hold it, or it does not exist / requires "
                    f"elevated privileges. Exiting.</>",
                )
                raise SystemExit(1) from None
            iface_ip4_host = ip4_host if single else None
            iface_ip6_host = ip6_host if single else None
            stack.add_interface(
                **interface_args,
                ip4_support=ip4_support,
                ip4_host=iface_ip4_host,
                ip4_dhcp=ip4_support and iface_ip4_host is None,
                ip6_support=ip6_support,
                ip6_host=iface_ip6_host,
                ip6_gua_autoconfig=ip6_support and iface_ip6_host is None,
            )
        # Bind the capture writer before 'stack.start()' so it records the
        # stack's own autoconfiguration (DAD / RS / RA / ARP ACD / DHCPv4)
        # from the first frame.
        if capture_path is not None:
            capture_state = _start_capture(capture_path, pcap=capture_pcap)
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
        # Stop the capture after 'stack.stop()' so the writer also records
        # the stack's graceful shutdown frames (IGMP / MLD leave, etc.).
        if capture_state is not None:
            _stop_capture(*capture_state)
        if pidfile_path is not None:
            remove_pidfile(pidfile_path)
