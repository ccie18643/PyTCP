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
This module contains the netcat ('nc') engine behind the 'pytcp nc'
CLI subcommand, built on the daemon-backed 'pytcp.socket' drop-in.

The engine is split so its logic is unit-testable without a daemon:
'parse_port' / 'parse_port_range' / 'resolve_endpoint' are pure helpers,
and the bidirectional relay is two independent pump functions
('_pump_input' stdin -> socket, '_pump_output' socket -> stdout) joined
by 'relay' (the input pump runs on a daemon thread while the output
pump drives the main loop), so a caller-supplied stream / socket double
exercises each direction. 'connect_endpoint', 'listen_endpoint', and
'scan_port' are the daemon-touching helpers.

It mirrors the netcat core: an outbound connect ('nc HOST PORT'), a
one-shot listen server ('-l'), a zero-I/O TCP port scan ('-z'), and a
UDP datagram mode ('-u') for each. The relay half-closes the write side
on stdin EOF (TCP) and keeps draining the peer until it closes, exactly
as 'nc' does.

packages/pytcp/pytcp/cli/cli__nc.py

ver 3.0.9
"""

import sys
import threading
from typing import Protocol, cast

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp import socket

NC__BUFSIZE: int = 65536
NC__DEFAULT_TIMEOUT__SEC: float = 10.0
PORT__MIN: int = 1
PORT__MAX: int = 65535


class NcError(Exception):
    """
    Exception raised for a 'pytcp nc' argument error (e.g. a bad port),
    reported cleanly by the CLI command.
    """


class _Readable(Protocol):
    """
    The binary input-stream surface the input pump depends on.
    """

    def read1(self, size: int, /) -> bytes: ...


class _Writable(Protocol):
    """
    The binary output-stream surface the output pump depends on.
    """

    def write(self, data: bytes, /) -> int: ...

    def flush(self) -> None: ...


def stdin_stream() -> _Readable:
    """
    Return the process stdin as a binary relay input stream. The runtime
    buffer is a 'BufferedReader' (it has the 'read1' the pumps use for
    line-responsive input); the cast pins that, since stdlib types its
    static type as a bare 'BinaryIO'.
    """

    return cast(_Readable, sys.stdin.buffer)


def parse_port(text: str, /) -> int:
    """
    Parse a single port number (1-65535), raising 'NcError' otherwise.
    """

    try:
        port = int(text)
    except ValueError:
        raise NcError(f"invalid port {text!r}") from None
    if not PORT__MIN <= port <= PORT__MAX:
        raise NcError(f"port out of range (1-65535): {text!r}")
    return port


def parse_port_range(text: str, /) -> tuple[int, int]:
    """
    Parse a port or inclusive 'LOW-HIGH' range into '(low, high)',
    raising 'NcError' on a malformed spec or a low-above-high range.
    """

    if "-" not in text:
        port = parse_port(text)
        return port, port
    low_text, _, high_text = text.partition("-")
    low, high = parse_port(low_text), parse_port(high_text)
    if low > high:
        raise NcError(f"port range start above end: {text!r}")
    return low, high


def resolve_endpoint(host: str, /, *, prefer_ipv6: bool = False) -> tuple[int, str]:
    """
    Resolve 'host' to '(family, address)'. An IP literal is classified
    directly via 'net_addr'; a name is resolved through the daemon's DNS
    resolver ('getaddrinfo'), preferring an IPv6 result when
    'prefer_ipv6' is set and one exists.
    """

    if _is_ipv6_literal(host):
        return int(socket.AF_INET6), host
    if _is_ipv4_literal(host):
        return int(socket.AF_INET), host

    infos = socket.getaddrinfo(host, None)
    if prefer_ipv6:
        infos = sorted(infos, key=lambda info: info[0] != socket.AF_INET6)
    family, _type, _proto, _canon, sockaddr = infos[0]
    return int(family), sockaddr[0]


def _is_ipv4_literal(host: str, /) -> bool:
    """
    Return whether 'host' is a valid IPv4 literal.
    """

    try:
        Ip4Address(host)
    except Ip4AddressFormatError:
        return False
    return True


def _is_ipv6_literal(host: str, /) -> bool:
    """
    Return whether 'host' is a valid IPv6 literal.
    """

    try:
        Ip6Address(host)
    except Ip6AddressFormatError:
        return False
    return True


def open_socket(*, family: int, is_udp: bool) -> socket.Socket:
    """
    Open a stream (TCP) or datagram (UDP) socket of the given family.
    """

    return socket.socket(family, socket.SOCK_DGRAM if is_udp else socket.SOCK_STREAM)


def connect_endpoint(
    *,
    host: str,
    port: int,
    is_udp: bool,
    timeout: float,
    prefer_ipv6: bool = False,
) -> tuple[socket.Socket, int, str]:
    """
    Resolve and connect to '(host, port)', returning '(socket, family,
    address)'. A UDP socket is merely opened (datagrams carry the peer);
    a TCP socket completes the handshake under 'timeout'.
    """

    family, address = resolve_endpoint(host, prefer_ipv6=prefer_ipv6)
    sock = open_socket(family=family, is_udp=is_udp)
    if not is_udp:
        sock.settimeout(timeout)
        sock.connect((address, port))
        sock.settimeout(None)
    return sock, family, address


def listen_endpoint(*, host: str, port: int, is_udp: bool) -> tuple[socket.Socket, int]:
    """
    Open, bind, and (for TCP) listen on '(host, port)', returning
    '(socket, family)'. The family follows the bind host literal
    (wildcard '0.0.0.0' / '::' select IPv4 / IPv6).
    """

    family = int(socket.AF_INET6) if _is_ipv6_literal(host) else int(socket.AF_INET)
    sock = open_socket(family=family, is_udp=is_udp)
    sock.bind((host, port))
    if not is_udp:
        sock.listen(1)
    return sock, family


def scan_port(*, host: str, port: int, timeout: float, prefer_ipv6: bool = False) -> bool:
    """
    Probe a single TCP port: attempt a connect under 'timeout' and report
    whether it succeeded (the port is open). The probe socket is always
    closed before returning.
    """

    family, address = resolve_endpoint(host, prefer_ipv6=prefer_ipv6)
    sock = open_socket(family=family, is_udp=False)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except OSError:
        return False
    finally:
        # Closing a probe socket whose connect timed out can itself time
        # out on the daemon round-trip; a close failure must never crash
        # the scan, so swallow it.
        try:
            sock.close()
        except OSError:
            pass
    return True


def _pump_input(sock: socket.Socket, input_stream: _Readable, /, *, half_close: bool) -> None:
    """
    Pump 'input_stream' into 'sock' until end-of-input, then half-close
    the write side (TCP) so the peer sees EOF while we keep reading.
    """

    try:
        while True:
            data = input_stream.read1(NC__BUFSIZE)
            if not data:
                break
            sock.sendall(data)
    except OSError:
        return
    if half_close:
        try:
            sock.shutdown(int(socket.SHUT_WR))
        except OSError:
            pass


def _pump_output(sock: socket.Socket, output_stream: _Writable, /) -> None:
    """
    Pump bytes received on 'sock' to 'output_stream' until the peer
    closes its write side ('recv' returns empty).
    """

    try:
        while True:
            data = sock.recv(NC__BUFSIZE)
            if not data:
                break
            output_stream.write(data)
            output_stream.flush()
    except OSError:
        return


def relay(
    sock: socket.Socket, /, *, input_stream: _Readable, output_stream: _Writable, half_close: bool = True
) -> None:
    """
    Run the bidirectional relay for a connected stream socket: the input
    pump runs on a daemon thread (so it can block on stdin) while the
    output pump drives the main loop and returns when the peer closes.
    """

    pump = threading.Thread(
        target=_pump_input,
        args=(sock, input_stream),
        kwargs={"half_close": half_close},
        daemon=True,
    )
    pump.start()
    _pump_output(sock, output_stream)


def _udp_pump_input(sock: socket.Socket, input_stream: _Readable, /, *, peer: tuple[str, int]) -> None:
    """
    Pump 'input_stream' into 'sock' as datagrams to 'peer' until
    end-of-input.
    """

    try:
        while True:
            data = input_stream.read1(NC__BUFSIZE)
            if not data:
                break
            sock.sendto(data, peer)
    except OSError:
        return


def _udp_pump_output(sock: socket.Socket, output_stream: _Writable, /) -> None:
    """
    Pump datagrams received on 'sock' to 'output_stream' until the socket
    times out (the idle deadline) or errors.
    """

    try:
        while True:
            data, _address = sock.recvfrom(NC__BUFSIZE)
            output_stream.write(data)
            output_stream.flush()
    except OSError, TimeoutError:
        return


def udp_relay(
    sock: socket.Socket,
    /,
    *,
    peer: tuple[str, int],
    input_stream: _Readable,
    output_stream: _Writable,
    idle_timeout: float | None = None,
) -> None:
    """
    Run the bidirectional relay for a UDP socket against 'peer'. The
    input pump runs on a daemon thread; the output pump drives the main
    loop and returns when the socket idles past 'idle_timeout' (or on
    error). With no idle timeout the output pump blocks until interrupted.
    """

    if idle_timeout is not None:
        sock.settimeout(idle_timeout)
    pump = threading.Thread(
        target=_udp_pump_input,
        args=(sock, input_stream),
        kwargs={"peer": peer},
        daemon=True,
    )
    pump.start()
    _udp_pump_output(sock, output_stream)


def format_verbose_connect(*, host: str, port: int, is_udp: bool) -> str:
    """
    Render the netcat-style 'connection succeeded' verbose line.
    """

    return f"Connection to {host} {port} port [{'udp' if is_udp else 'tcp'}/*] succeeded!"


def format_scan_result(*, host: str, port: int, is_open: bool) -> str:
    """
    Render a netcat-style port-scan result line.
    """

    if is_open:
        return f"Connection to {host} {port} port [tcp/*] succeeded!"
    return f"nc: connect to {host} port {port} (tcp) failed: Connection refused"
