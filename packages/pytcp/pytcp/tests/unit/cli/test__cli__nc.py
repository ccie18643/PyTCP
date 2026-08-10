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
This module contains unit tests for the daemon-independent parts of the
'pytcp nc' netcat engine — the pure parsing / resolution helpers, the
bidirectional relay pumps (driven against socket doubles and a real
socketpair), and the connect / scan / listen helpers.

packages/pytcp/pytcp/tests/unit/cli/test__cli__nc.py

ver 3.0.10
"""

import io
import socket as std_socket
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from threading import Thread
from unittest import TestCase
from unittest.mock import create_autospec, patch

import pytcp.cli.__main__ as cli_main
import pytcp.cli.cli__nc as nc
from pytcp import socket


class _FakeStreamSocket:
    """
    A stream-socket double recording connect / bind / listen / timeout /
    close, optionally raising a preset error on connect.
    """

    def __init__(self, *, connect_error: OSError | None = None, close_error: OSError | None = None) -> None:
        self._connect_error = connect_error
        self._close_error = close_error
        self.connected: tuple[str, int] | None = None
        self.bound: tuple[str, int] | None = None
        self.listen_backlog: int | None = None
        self.timeouts: list[float | None] = []
        self.closed = False

    def settimeout(self, value: float | None, /) -> None:
        self.timeouts.append(value)

    def connect(self, address: tuple[str, int], /) -> None:
        if self._connect_error is not None:
            raise self._connect_error
        self.connected = address

    def bind(self, address: tuple[str, int], /) -> None:
        self.bound = address

    def listen(self, backlog: int = 128, /) -> None:
        self.listen_backlog = backlog

    def close(self) -> None:
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class _FakeUdpSocket:
    """
    A datagram-socket double recording sent datagrams and replaying a
    queue of incoming '(data, address)' pairs, then timing out.
    """

    def __init__(self, incoming: list[tuple[bytes, tuple[str, int]]], /) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self._incoming = incoming
        self.timeout: float | None = None

    def settimeout(self, value: float | None, /) -> None:
        self.timeout = value

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        self.sent.append((data, address))
        return len(data)

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, tuple[str, int]]:
        if self._incoming:
            return self._incoming.pop(0)
        raise TimeoutError


class TestNcParsePort(TestCase):
    """
    The single-port parser tests.
    """

    def test__cli__nc__parse_port_accepts_valid(self) -> None:
        """
        Ensure a valid port string parses to its integer value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(nc.parse_port("443"), 443, msg="A valid port string must parse to its integer value.")

    def test__cli__nc__parse_port_rejects_out_of_range(self) -> None:
        """
        Ensure a port outside 1-65535 raises NcError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(nc.NcError):
            nc.parse_port("70000")

    def test__cli__nc__parse_port_rejects_non_numeric(self) -> None:
        """
        Ensure a non-numeric port raises NcError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(nc.NcError):
            nc.parse_port("http")


class TestNcParsePortRange(TestCase):
    """
    The port-range parser tests.
    """

    def test__cli__nc__parse_port_range_single(self) -> None:
        """
        Ensure a single port yields a one-port inclusive range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(nc.parse_port_range("80"), (80, 80), msg="A single port must yield a one-port range.")

    def test__cli__nc__parse_port_range_low_high(self) -> None:
        """
        Ensure a 'LOW-HIGH' spec yields the inclusive bounds.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(nc.parse_port_range("20-25"), (20, 25), msg="A 'LOW-HIGH' spec must yield the bounds.")

    def test__cli__nc__parse_port_range_rejects_inverted(self) -> None:
        """
        Ensure a range whose start exceeds its end raises NcError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(nc.NcError):
            nc.parse_port_range("30-20")


class TestNcResolveEndpoint(TestCase):
    """
    The endpoint-resolution helper tests.
    """

    def test__cli__nc__resolve_ipv4_literal(self) -> None:
        """
        Ensure an IPv4 literal classifies directly without a DNS lookup.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            nc.resolve_endpoint("10.0.1.5"),
            (int(socket.AF_INET), "10.0.1.5"),
            msg="An IPv4 literal must classify to the INET family and itself.",
        )

    def test__cli__nc__resolve_ipv6_literal(self) -> None:
        """
        Ensure an IPv6 literal classifies directly without a DNS lookup.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            nc.resolve_endpoint("2001:db8::1"),
            (int(socket.AF_INET6), "2001:db8::1"),
            msg="An IPv6 literal must classify to the INET6 family and itself.",
        )

    def test__cli__nc__resolve_name_uses_getaddrinfo(self) -> None:
        """
        Ensure a host name resolves through the daemon's getaddrinfo.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        infos = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
        with patch("pytcp.socket.getaddrinfo", autospec=True, return_value=infos):
            self.assertEqual(
                nc.resolve_endpoint("example.com"),
                (int(socket.AF_INET), "93.184.216.34"),
                msg="A host name must resolve through getaddrinfo to its address.",
            )


class TestNcPumps(TestCase):
    """
    The TCP relay pump tests.
    """

    def test__cli__nc__pump_output_drains_until_peer_close(self) -> None:
        """
        Ensure the output pump writes every received chunk and stops when
        recv returns empty.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        sock = create_autospec(socket.Socket, spec_set=True)
        sock.recv.side_effect = [b"foo", b"bar", b""]
        out = io.BytesIO()

        nc._pump_output(sock, out)

        self.assertEqual(out.getvalue(), b"foobar", msg="The output pump must drain every chunk until peer close.")

    def test__cli__nc__pump_input_sends_then_half_closes(self) -> None:
        """
        Ensure the input pump forwards stdin and half-closes the write
        side on end-of-input.

        Reference: RFC 9293 §3.6 (Closing a connection).
        """

        sock = create_autospec(socket.Socket, spec_set=True)

        nc._pump_input(sock, io.BytesIO(b"payload"), half_close=True)

        sock.sendall.assert_called_once_with(b"payload")
        sock.shutdown.assert_called_once_with(int(socket.SHUT_WR))

    def test__cli__nc__pump_input_no_half_close_skips_shutdown(self) -> None:
        """
        Ensure the input pump does not shut the write side when half-close
        is disabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = create_autospec(socket.Socket, spec_set=True)

        nc._pump_input(sock, io.BytesIO(b"payload"), half_close=False)

        sock.shutdown.assert_not_called()


class TestNcRelay(TestCase):
    """
    The bidirectional relay tests (over a real socketpair).
    """

    def test__cli__nc__relay_pipes_both_directions(self) -> None:
        """
        Ensure the relay forwards stdin to the peer and the peer's bytes
        to stdout, ending when the peer closes its write side.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        near, far = std_socket.socketpair()
        self.addCleanup(near.close)
        self.addCleanup(far.close)

        output = io.BytesIO()
        worker = Thread(
            target=nc.relay,
            args=(near,),
            kwargs={"input_stream": io.BytesIO(b"client-data"), "output_stream": output},
            daemon=True,
        )
        worker.start()

        received = b""
        while len(received) < len(b"client-data"):
            received += far.recv(1024)
        far.sendall(b"server-reply")
        far.shutdown(std_socket.SHUT_WR)
        worker.join(timeout=5.0)

        self.assertEqual(
            (received, output.getvalue()),
            (b"client-data", b"server-reply"),
            msg="The relay must pipe stdin to the peer and the peer's reply to stdout.",
        )


class TestNcUdpPumps(TestCase):
    """
    The UDP relay pump tests.
    """

    def test__cli__nc__udp_pump_input_sends_to_peer(self) -> None:
        """
        Ensure the UDP input pump sends stdin as a datagram to the peer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeUdpSocket([])

        nc._udp_pump_input(sock, io.BytesIO(b"datagram"), peer=("9.9.9.9", 53))  # type: ignore[arg-type]

        self.assertEqual(
            sock.sent,
            [(b"datagram", ("9.9.9.9", 53))],
            msg="The UDP input pump must send stdin to the peer.",
        )

    def test__cli__nc__udp_pump_output_writes_until_idle(self) -> None:
        """
        Ensure the UDP output pump writes each datagram and stops when the
        socket idles (times out).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeUdpSocket([(b"reply-1", ("9.9.9.9", 53)), (b"reply-2", ("9.9.9.9", 53))])
        out = io.BytesIO()

        nc._udp_pump_output(sock, out)  # type: ignore[arg-type]

        self.assertEqual(out.getvalue(), b"reply-1reply-2", msg="The UDP output pump must write each datagram.")


class TestNcConnectEndpoint(TestCase):
    """
    The connect helper tests.
    """

    def test__cli__nc__connect_tcp_completes_handshake(self) -> None:
        """
        Ensure a TCP connect resolves, sets the connect timeout, connects,
        and clears the timeout for the relay.

        Reference: RFC 9293 §3.5 (Connection establishment).
        """

        sock = _FakeStreamSocket()
        with (
            patch.object(nc, "resolve_endpoint", autospec=True, return_value=(int(socket.AF_INET), "10.0.1.5")),
            patch.object(nc, "open_socket", autospec=True, return_value=sock),
        ):
            result, family, address = nc.connect_endpoint(host="server", port=80, is_udp=False, timeout=4.0)

        self.assertIs(result, sock, msg="A TCP connect must return the opened socket.")
        self.assertEqual(
            (family, address, sock.connected, sock.timeouts),
            (int(socket.AF_INET), "10.0.1.5", ("10.0.1.5", 80), [4.0, None]),
            msg="A TCP connect must resolve, time the handshake, connect, then clear the timeout.",
        )

    def test__cli__nc__connect_udp_does_not_handshake(self) -> None:
        """
        Ensure a UDP 'connect' merely opens the socket without a handshake.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeStreamSocket()
        with (
            patch.object(nc, "resolve_endpoint", autospec=True, return_value=(int(socket.AF_INET), "10.0.1.5")),
            patch.object(nc, "open_socket", autospec=True, return_value=sock),
        ):
            nc.connect_endpoint(host="server", port=53, is_udp=True, timeout=4.0)

        self.assertEqual(
            (sock.connected, sock.timeouts),
            (None, []),
            msg="A UDP connect must not perform a handshake or set a timeout.",
        )


class TestNcScanPort(TestCase):
    """
    The port-scan helper tests.
    """

    def test__cli__nc__scan_port_open(self) -> None:
        """
        Ensure a successful connect reports the port open and closes the
        probe socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeStreamSocket()
        with (
            patch.object(nc, "resolve_endpoint", autospec=True, return_value=(int(socket.AF_INET), "10.0.1.5")),
            patch.object(nc, "open_socket", autospec=True, return_value=sock),
        ):
            result = nc.scan_port(host="server", port=80, timeout=2.0)

        self.assertEqual((result, sock.closed), (True, True), msg="An accepting port must scan open and be closed.")

    def test__cli__nc__scan_port_closed(self) -> None:
        """
        Ensure a refused connect reports the port closed and still closes
        the probe socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeStreamSocket(connect_error=ConnectionRefusedError("refused"))
        with (
            patch.object(nc, "resolve_endpoint", autospec=True, return_value=(int(socket.AF_INET), "10.0.1.5")),
            patch.object(nc, "open_socket", autospec=True, return_value=sock),
        ):
            result = nc.scan_port(host="server", port=81, timeout=2.0)

        self.assertEqual((result, sock.closed), (False, True), msg="A refused port must scan closed and be closed.")

    def test__cli__nc__scan_port_survives_close_failure(self) -> None:
        """
        Ensure a probe whose socket close itself raises (the daemon
        round-trip timing out after a filtered-port connect) still
        returns the connect result instead of propagating the close
        error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeStreamSocket(
            connect_error=TimeoutError("timed out"),
            close_error=TimeoutError("close timed out"),
        )
        with (
            patch.object(nc, "resolve_endpoint", autospec=True, return_value=(int(socket.AF_INET), "10.0.1.5")),
            patch.object(nc, "open_socket", autospec=True, return_value=sock),
        ):
            result = nc.scan_port(host="server", port=81, timeout=2.0)

        self.assertFalse(result, msg="A filtered port whose close fails must still scan closed without raising.")


class TestNcListenEndpoint(TestCase):
    """
    The listen helper tests.
    """

    def test__cli__nc__listen_tcp_binds_and_listens(self) -> None:
        """
        Ensure a TCP listen binds the wildcard address and listens.

        Reference: RFC 9293 §3.5 (Connection establishment, passive open).
        """

        sock = _FakeStreamSocket()
        with patch.object(nc, "open_socket", autospec=True, return_value=sock):
            result, family = nc.listen_endpoint(host="0.0.0.0", port=8080, is_udp=False)

        self.assertIs(result, sock, msg="A TCP listen must return the opened socket.")
        self.assertEqual(
            (family, sock.bound, sock.listen_backlog),
            (int(socket.AF_INET), ("0.0.0.0", 8080), 1),
            msg="A TCP listen must bind the address and listen with backlog 1.",
        )

    def test__cli__nc__listen_ipv6_host_selects_inet6(self) -> None:
        """
        Ensure an IPv6 bind host selects the INET6 family.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeStreamSocket()
        with patch.object(nc, "open_socket", autospec=True, return_value=sock):
            _result, family = nc.listen_endpoint(host="::", port=8080, is_udp=False)

        self.assertEqual(
            family,
            int(socket.AF_INET6),
            msg="An IPv6 bind host must select the INET6 family.",
        )


class TestCliNcCommand(TestCase):
    """
    The 'pytcp nc' command-wiring tests (engine helpers faked, no daemon).
    """

    def _run(self, *argv: str, capture_stdout: bool = False) -> tuple[int, str, str]:
        """
        Run 'main(["nc", *argv])', capturing stderr (and stdout when
        'capture_stdout' is set — the relay paths read sys.stdout.buffer,
        which a redirected StringIO lacks).
        """

        out, err = io.StringIO(), io.StringIO()
        out_ctx = redirect_stdout(out) if capture_stdout else nullcontext()
        with out_ctx, redirect_stderr(err):
            code = cli_main.main(["nc", *argv])
        return code, out.getvalue(), err.getvalue()

    def test__cli__nc__connect_invokes_relay_and_exits_zero(self) -> None:
        """
        Ensure an outbound connect runs the relay against the connected
        socket and closes it on exit.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        sock = create_autospec(socket.Socket, spec_set=True)
        with (
            patch.object(
                cli_main, "connect_endpoint", autospec=True, return_value=(sock, int(socket.AF_INET), "1.2.3.4")
            ),
            patch.object(cli_main, "relay", autospec=True) as relay_mock,
        ):
            code, _out, _err = self._run("example.com", "80")

        self.assertEqual(code, 0, msg="A successful connect must exit 0.")
        self.assertIs(relay_mock.call_args.args[0], sock, msg="The relay must run against the connected socket.")
        sock.close.assert_called_once_with()

    def test__cli__nc__connect_refused_reports_and_exits_one(self) -> None:
        """
        Ensure a refused connect prints the netcat-style failure line and
        exits non-zero.

        Reference: RFC 9293 §3.5 (Connection establishment).
        """

        with patch.object(
            cli_main, "connect_endpoint", autospec=True, side_effect=ConnectionRefusedError("Connection refused")
        ):
            code, _out, err = self._run("example.com", "80")

        self.assertEqual(code, 1, msg="A refused connect must exit 1.")
        self.assertIn("connect to example.com port 80", err, msg="The failure line must name the host and port.")

    def test__cli__nc__connect_daemon_down_reports_cleanly(self) -> None:
        """
        Ensure a missing daemon data socket prints the canonical daemon
        diagnostic and exits non-zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(
            cli_main, "connect_endpoint", autospec=True, side_effect=FileNotFoundError(2, "No such file or directory")
        ):
            code, _out, err = self._run("example.com", "80")

        self.assertEqual((code, "daemon" in err.lower()), (1, True), msg="A down daemon must exit 1 with a diagnostic.")

    def test__cli__nc__connect_missing_port_errors(self) -> None:
        """
        Ensure an outbound connect with no port is rejected cleanly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        code, _out, err = self._run("example.com")

        self.assertEqual((code, "port" in err.lower()), (1, True), msg="A missing port must exit 1 with a diagnostic.")

    def test__cli__nc__udp_connect_invokes_udp_relay(self) -> None:
        """
        Ensure a UDP connect runs the UDP relay against the resolved peer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = create_autospec(socket.Socket, spec_set=True)
        with (
            patch.object(
                cli_main, "connect_endpoint", autospec=True, return_value=(sock, int(socket.AF_INET), "9.9.9.9")
            ),
            patch.object(cli_main, "udp_relay", autospec=True) as udp_relay_mock,
        ):
            code, _out, _err = self._run("-u", "resolver", "53")

        self.assertEqual(code, 0, msg="A UDP connect must exit 0.")
        self.assertEqual(
            udp_relay_mock.call_args.kwargs["peer"],
            ("9.9.9.9", 53),
            msg="The UDP relay must target the resolved peer.",
        )

    def test__cli__nc__listen_accepts_and_relays(self) -> None:
        """
        Ensure a TCP listen accepts one connection, relays it, and closes
        both the connection and the listener.

        Reference: RFC 9293 §3.5 (Connection establishment, passive open).
        """

        conn = create_autospec(socket.Socket, spec_set=True)
        listener = create_autospec(socket.Socket, spec_set=True)
        listener.accept.return_value = (conn, ("10.0.1.9", 50000))
        with (
            patch.object(cli_main, "listen_endpoint", autospec=True, return_value=(listener, int(socket.AF_INET))),
            patch.object(cli_main, "relay", autospec=True) as relay_mock,
        ):
            code, _out, _err = self._run("-l", "8080")

        self.assertEqual(code, 0, msg="A completed listen session must exit 0.")
        self.assertIs(relay_mock.call_args.args[0], conn, msg="The relay must run against the accepted connection.")
        conn.close.assert_called_once_with()
        listener.close.assert_called_once_with()

    def test__cli__nc__scan_reports_open_ports_and_exits_zero(self) -> None:
        """
        Ensure a port-range scan prints a line per open port and exits
        zero when at least one is open.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def fake_scan(*, host: str, port: int, timeout: float, prefer_ipv6: bool) -> bool:
            return port == 80

        with patch.object(cli_main, "scan_port", autospec=True, side_effect=fake_scan):
            code, out, _err = self._run("-z", "example.com", "80-81", capture_stdout=True)

        self.assertEqual(code, 0, msg="A scan finding an open port must exit 0.")
        self.assertIn("example.com 80 port", out, msg="The open port must be reported.")
        self.assertNotIn("81 port", out, msg="The closed port must not be reported without verbose.")

    def test__cli__nc__scan_no_open_exits_one(self) -> None:
        """
        Ensure a scan finding no open ports exits non-zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(cli_main, "scan_port", autospec=True, return_value=False):
            code, _out, _err = self._run("-z", "example.com", "80", capture_stdout=True)

        self.assertEqual(code, 1, msg="A scan finding no open port must exit 1.")

    def test__cli__nc__scan_udp_rejected(self) -> None:
        """
        Ensure combining '-z' with '-u' is rejected cleanly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        code, _out, err = self._run("-z", "-u", "example.com", "80", capture_stdout=True)

        self.assertEqual((code, "UDP" in err), (1, True), msg="A UDP scan must be rejected with a diagnostic.")
