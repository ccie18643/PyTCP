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
This module contains tests for the 'UdpSocket' BSD-like UDP socket
implementation.

pytcp/tests/unit/runtime/socket/test__runtime__socket__udp__socket.py

ver 3.0.10
"""

import errno
import fcntl
import select
from types import SimpleNamespace
from typing import Any, override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.socket import (
    IP_TOS,
    IPPROTO_IP,
    SO_BROADCAST,
    SO_RCVBUF,
    SO_RCVTIMEO,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_SNDBUF,
    SO_SNDTIMEO,
    SOL_SOCKET,
    AddressFamily,
    SocketType,
    gaierror,
)
from pytcp.runtime.socket.socket_table import SocketTable
from pytcp.runtime.socket.udp__metadata import UdpMetadata
from pytcp.runtime.socket.udp__socket import UdpSocket


def _make_packet_handler(
    *,
    ip4_unicast: list[Ip4Address] | None = None,
    ip6_unicast: list[Ip6Address] | None = None,
    tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING,
) -> SimpleNamespace:
    """
    Build a minimal 'packet_handler' stub exposing the unicast address
    iterables plus a 'send_udp_packet' callable that returns the
    requested 'TxStatus'.
    """

    return SimpleNamespace(
        ip4_unicast=ip4_unicast or [Ip4Address("10.0.0.1")],
        ip6_unicast=ip6_unicast or [Ip6Address("2001:db8::1")],
        send_udp_packet=lambda **_: tx_status,
    )


class _UdpSocketTestCase(TestCase):
    """
    Shared fixture for 'UdpSocket' tests that stubs the stack's module
    globals ('sockets', 'packet_handler') and suppresses log output.
    """

    @override
    def setUp(self) -> None:
        """
        Install the module-level stack patches and a fresh, empty
        socket registry.

        Patches are torn down via 'addCleanup' rather than an
        explicit 'tearDown' so test-level 'self.addCleanup(s.close)'
        callbacks (registered later, LIFO-popped first) run while
        the 'log' patch is still active. Otherwise socket close
        logs leak through to stdout — see test-suite invariants
        in unit_testing.md.
        """

        self._log_patch = patch("pytcp.runtime.socket.udp__socket.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._sockets = SocketTable()
        self._sockets_patch = patch(
            "pytcp.runtime.socket.udp__socket.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()
        self.addCleanup(self._sockets_patch.stop)

        self._handler = _make_packet_handler()

        # Socket-originated TX resolves its egress interface through
        # 'stack.egress_packet_handler()' (the Phase-6 seam). Point it at
        # this fixture's local stub handler; reading 'self._handler' lazily
        # lets a per-test reassignment (e.g. a DROPPED-tx_status stub)
        # transparently drive the send path.
        self._egress_patch = patch(
            "pytcp.runtime.socket.udp__socket.stack.egress_packet_handler",
            side_effect=lambda *_a: self._handler,
        )
        self._egress_patch.start()
        self.addCleanup(self._egress_patch.stop)

        # These fixtures stub the whole TX path via the egress handler
        # above; routing is not under test, so the no-route EHOSTUNREACH
        # check is pinned True (otherwise a FIB leaked into globals by an
        # earlier suite test would spuriously fail these sends).
        self._has_route_patch = patch(
            "pytcp.runtime.socket.udp__socket.stack.has_route_to",
            return_value=True,
        )
        self._has_route_patch.start()
        self.addCleanup(self._has_route_patch.stop)

        # Source-address validation now spans all interfaces via the
        # 'stack.local_ip{4,6}_unicast()' introspection helpers (Phase-6
        # cross-interface seam). Make them read this fixture's local stub.
        for _helper, _attr in (("local_ip4_unicast", "ip4_unicast"), ("local_ip6_unicast", "ip6_unicast")):
            _p = patch(
                f"pytcp.runtime.socket.udp__socket.stack.{_helper}",
                side_effect=lambda attr=_attr: tuple(getattr(self._handler, attr)),
            )
            _p.start()
            self.addCleanup(_p.stop)

        # is_address_in_use reads stack.sockets directly, so mirror the
        # patch on that module as well.
        self._helper_sockets_patch = patch(
            "pytcp.runtime.socket.socket__bind_helpers.stack.sockets",
            self._sockets,
        )
        self._helper_sockets_patch.start()
        self.addCleanup(self._helper_sockets_patch.stop)


class TestUdpSocketInit(_UdpSocketTestCase):
    """
    The 'UdpSocket.__init__' tests.
    """

    def test__udp_socket__init_ip4_defaults(self) -> None:
        """
        Ensure a fresh IPv4 UDP socket starts with unspecified
        local/remote IPs, both ports at 0, and the fixed socket_type
        + ip_proto mix.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.assertIs(s.socket_type, SocketType.DGRAM, msg="socket_type must be DGRAM.")
        self.assertIs(s.ip_proto, IpProto.UDP, msg="ip_proto must be UDP.")
        self.assertEqual(s.local_ip_address, Ip4Address(), msg="local_ip_address must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip4Address(), msg="remote_ip_address must start unspecified.")
        self.assertEqual(s.local_port, 0, msg="local_port must start at 0.")
        self.assertEqual(s.remote_port, 0, msg="remote_port must start at 0.")

    def test__udp_socket__init_ip6_defaults(self) -> None:
        """
        Ensure a fresh IPv6 UDP socket starts with the '::' unspecified
        address on both ends.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET6)
        self.assertEqual(s.local_ip_address, Ip6Address(), msg="IPv6 local_ip_address must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip6Address(), msg="IPv6 remote_ip_address must start unspecified.")

    def test__udp_socket__init_rejects_non_dgram(self) -> None:
        """
        Ensure the 'assert type is SocketType.DGRAM' guard fires when
        a non-DGRAM socket type is supplied.

        Reference: RFC 768 (UDP user interface).
        """

        with self.assertRaises(AssertionError):
            UdpSocket(family=AddressFamily.INET4, type=SocketType.STREAM)

    def test__udp_socket__init_rejects_non_udp_protocol(self) -> None:
        """
        Ensure the 'assert protocol is IpProto.UDP' guard fires for a
        non-UDP protocol argument.

        Reference: RFC 768 (UDP user interface).
        """

        with self.assertRaises(AssertionError):
            UdpSocket(family=AddressFamily.INET4, protocol=IpProto.TCP)


class TestUdpSocketBind(_UdpSocketTestCase):
    """
    The 'UdpSocket.bind' tests.
    """

    def test__udp_socket__bind_picks_port_when_zero(self) -> None:
        """
        Ensure bind() with a zero local port defers to
        'pick_local_port' and registers the resulting port on the
        socket.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with patch(
            "pytcp.runtime.socket.udp__socket.pick_local_port",
            return_value=40000,
        ):
            s.bind(("10.0.0.1", 0))
        self.assertEqual(
            s.local_port,
            40000,
            msg="bind() with local port 0 must assign the port picked by pick_local_port.",
        )

    def test__udp_socket__bind_with_specific_port(self) -> None:
        """
        Ensure bind() with a specific local port accepts it when no
        other socket is using it.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        self.assertEqual(s.local_port, 8080, msg="bind() with a specific port must use that port verbatim.")

    def test__udp_socket__bind_twice_raises(self) -> None:
        """
        Ensure binding an already-bound socket raises 'OSError' with
        Errno 22 — the socket can be bound exactly once.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        with self.assertRaises(OSError) as context:
            s.bind(("10.0.0.1", 8081))
        self.assertIn(
            "[Errno 22]",
            str(context.exception),
            msg="bind() must raise Errno 22 when called on a socket bound to a specific port.",
        )

    def test__udp_socket__bind_rejects_out_of_range_port(self) -> None:
        """
        Ensure bind() raises 'OverflowError' for a port value outside
        the 0-65535 range.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.bind(("10.0.0.1", 70000))

    def test__udp_socket__bind_rejects_foreign_ip(self) -> None:
        """
        Ensure bind() to a specific IPv4 address not owned by the
        stack raises 'OSError' with Errno 99.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise Errno 99 when the local IP is not stack-owned.",
        )

    def test__udp_socket__bind_rejects_malformed_ip(self) -> None:
        """
        Ensure a malformed IPv4 literal raises 'gaierror'.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.bind(("garbage", 0))

    def test__udp_socket__bind_ip6_accepts_stack_owned(self) -> None:
        """
        Ensure bind() on an IPv6 socket accepts a stack-owned address.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET6)
        s.bind(("2001:db8::1", 9090))
        self.assertEqual(
            s.local_ip_address,
            Ip6Address("2001:db8::1"),
            msg="bind() must set local_ip_address on an IPv6 socket.",
        )

    def test__udp_socket__bind_ip6_rejects_malformed(self) -> None:
        """
        Ensure a malformed IPv6 literal raises 'gaierror'.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET6)
        with self.assertRaises(gaierror):
            s.bind(("not-a-v6", 0))

    def test__udp_socket__bind_rejects_port_in_use(self) -> None:
        """
        Ensure bind() to a port already claimed by another socket
        raises 'OSError' with Errno 98.

        Reference: RFC 768 (UDP user interface).
        """

        first = UdpSocket(family=AddressFamily.INET4)
        first.bind(("10.0.0.1", 8080))

        second = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))
        self.assertIn(
            "[Errno 98]",
            str(context.exception),
            msg="bind() must raise Errno 98 when the (IP, port) is already in use.",
        )


class TestUdpSocketConnect(_UdpSocketTestCase):
    """
    The 'UdpSocket.connect' tests.
    """

    def test__udp_socket__connect_sets_remote_and_picks_local(self) -> None:
        """
        Ensure connect() picks a local IP via 'pick_local_ip_address'
        when unspecified, picks a local port via 'pick_local_port'
        when unbound, and stores both sides of the remote address.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 5353))

        self.assertEqual(s.local_ip_address, Ip4Address("10.0.0.1"), msg="connect() must pick the local IP.")
        self.assertEqual(s.local_port, 40000, msg="connect() must pick the local port.")
        self.assertEqual(s.remote_ip_address, Ip4Address("10.0.0.5"), msg="connect() must store the remote IP.")
        self.assertEqual(s.remote_port, 5353, msg="connect() must store the remote port.")

    def test__udp_socket__connect_rejects_out_of_range_port(self) -> None:
        """
        Ensure connect() raises 'OverflowError' for a remote port
        outside the 0-65535 range.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.connect(("10.0.0.5", 70000))

    def test__udp_socket__connect_rejects_malformed_address(self) -> None:
        """
        Ensure a malformed remote-address literal raises 'gaierror'.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.connect(("garbage", 7))

    def test__udp_socket__connect_unspecified_remote_marks_unreachable(self) -> None:
        """
        Ensure connecting to '0.0.0.0' (unspecified) flips the internal
        'unreachable' flag, which translates to 'ConnectionRefusedError'
        on the next send()/recv() call.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with patch(
            "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            with patch("pytcp.runtime.socket.udp__socket.pick_local_port", return_value=40000):
                s.connect(("0.0.0.0", 7))
        self.assertTrue(
            s._unreachable,
            msg="connect() to the unspecified remote address must mark the socket unreachable.",
        )


class TestUdpSocketSend(_UdpSocketTestCase):
    """
    The 'UdpSocket.send' / 'UdpSocket.sendto' tests.
    """

    def _connected_socket(self) -> UdpSocket:
        """
        Construct a connected IPv4 UDP socket ready for send().
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 5353))
        return s  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__udp_socket__send_requires_connect(self) -> None:
        """
        Ensure send() raises 'OSError' with Errno 89 when neither the
        remote IP nor the remote port is set.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            s.send(b"data")
        self.assertIn(
            "[Errno 89]",
            str(context.exception),
            msg="send() must raise Errno 89 when no destination is set.",
        )

    def test__udp_socket__send_returns_bytes_sent(self) -> None:
        """
        Ensure send() returns 'len(data)' when 'send_udp_packet'
        reports 'PASSED__ETHERNET__TO_TX_RING'.

        Reference: RFC 768 (UDP user interface).
        """

        s = self._connected_socket()
        self.assertEqual(s.send(b"hello"), 5, msg="send() must return len(data) on success.")

    def test__udp_socket__send_returns_len_data_even_on_drop(self) -> None:
        """
        Ensure send() returns 'len(data)' even when the TX path would
        ultimately drop the datagram. Phase 4b made the UDP send path
        fire-and-forget: the datagram is "accepted into the stack" the
        moment it is queued on the TX worker, matching Linux's
        queued-on-send UDP semantics. Delivery failures surface
        asynchronously (ICMP -> error queue), never via send()'s
        return value.

        Reference: RFC 768 (UDP user interface).
        """

        # Point the egress seam at a DROPPED-tx_status stub (the fixture's
        # 'egress_packet_handler' side_effect reads 'self._handler' lazily).
        self._handler = _make_packet_handler(tx_status=TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL)
        s = self._connected_socket()
        self.assertEqual(
            s.send(b"data"),
            4,
            msg="send() must return len(data) — fire-and-forget accepts the datagram regardless of drop.",
        )

    def test__udp_socket__send_clears_unreachable_and_raises(self) -> None:
        """
        Ensure send() on a socket flagged unreachable clears the flag
        and raises 'ConnectionRefusedError' — subsequent send()s see
        a clean state.

        Reference: RFC 768 (UDP user interface).
        """

        s = self._connected_socket()
        s.notify_unreachable()
        with self.assertRaises(ConnectionRefusedError):
            s.send(b"data")
        self.assertFalse(
            s._unreachable,
            msg="send() must clear the unreachable flag after translating it into ConnectionRefusedError.",
        )

    def test__udp_socket__sendto_does_not_require_connect(self) -> None:
        """
        Ensure sendto() works on an unbound socket — it picks a local
        port via 'pick_local_port' and derives the remote from its
        argument.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            self.assertEqual(
                s.sendto(b"hello", ("10.0.0.5", 5353)),
                5,
                msg="sendto() must return len(data) on success without requiring connect().",
            )

    def test__udp_socket__sendto_rejects_out_of_range_port(self) -> None:
        """
        Ensure sendto() raises 'OverflowError' for a remote port
        outside the 0-65535 range.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.sendto(b"data", ("10.0.0.5", 70000))

    def test__udp_socket__sendto_uses_existing_local_port(self) -> None:
        """
        Ensure sendto() on an already-bound socket reuses the existing
        local port rather than picking a new one.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 4444))
        with patch(
            "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.sendto(b"hello", ("10.0.0.5", 5353))
        self.assertEqual(
            s.local_port,
            4444,
            msg="sendto() must reuse the existing local_port of a bound socket.",
        )


class TestUdpSocketSendmsg(_UdpSocketTestCase):
    """
    The 'UdpSocket.sendmsg' tests.
    """

    def _connected_socket(self) -> UdpSocket:
        """
        Construct a connected IPv4 UDP socket ready for sendmsg().
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 5353))
        return s  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def _capture_payload(self) -> dict[str, Any]:
        """
        Replace the fixture handler's 'send_udp_packet' with a stub
        that captures its keyword arguments, and return the capture
        dict so a test can assert on the transmitted payload.
        """

        captured: dict[str, Any] = {}

        def _send_udp_packet(**kwargs: Any) -> TxStatus:
            captured.update(kwargs)
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        self._handler.send_udp_packet = _send_udp_packet
        return captured

    def test__udp_socket__sendmsg_concatenates_buffers(self) -> None:
        """
        Ensure sendmsg() concatenates the scatter-gather 'buffers'
        iterable into a single datagram payload and returns the total
        byte count, matching stdlib 'socket.sendmsg' semantics.

        Reference: RFC 768 (UDP user interface).
        """

        s = self._connected_socket()
        captured = self._capture_payload()

        self.assertEqual(
            s.sendmsg([b"AB", b"CD"]),
            4,
            msg="sendmsg() must return the total length of all concatenated buffers.",
        )
        self.assertEqual(
            captured["udp__payload"],
            b"ABCD",
            msg="sendmsg() must transmit the buffers concatenated in order.",
        )

    def test__udp_socket__sendmsg_with_address_unconnected(self) -> None:
        """
        Ensure sendmsg() with an explicit 'address' on an unconnected
        socket behaves like sendto() — it binds a local port and sends
        to the supplied destination.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            self.assertEqual(
                s.sendmsg([b"hi"], address=("10.0.0.5", 5353)),
                2,
                msg="sendmsg(address=...) must send like sendto() and return the byte count.",
            )

    def test__udp_socket__sendmsg_honors_ip_tos_cmsg(self) -> None:
        """
        Ensure sendmsg() with an IPv4 IP_TOS ancillary control message
        marks the outbound datagram's DSCP + ECN from that per-send TOS
        byte (the send-direction mirror of the IP_RECVTOS recvmsg path),
        overriding the socket's default TOS.

        Reference: RFC 1122 §4.1.4 (application control of the TOS byte).
        Reference: RFC 2474 §3 (DSCP is the high 6 bits of the TOS byte).
        """

        s = self._connected_socket()
        captured = self._capture_payload()

        # TOS 0x2a -> DSCP 0x0a (42 >> 2 = 10), ECN 0x02 (42 & 3).
        s.sendmsg([b"x"], [(int(IPPROTO_IP), int(IP_TOS), b"\x2a")])

        self.assertEqual(
            (captured["ip__dscp"], captured["ip__ecn"]),
            (0x0A, 0x02),
            msg="sendmsg() must set the outbound DSCP + ECN from the IP_TOS cmsg.",
        )

    def test__udp_socket__sendmsg_ignores_unknown_cmsg(self) -> None:
        """
        Ensure sendmsg() accepts a well-formed but unrecognised
        ancillary-data list and silently ignores it (matching Linux's
        silent-ignore of unhandled cmsgs), leaving the socket's default
        TOS in place.

        Reference: socket(7) sendmsg (ancillary-data ignore).
        """

        s = self._connected_socket()
        captured = self._capture_payload()

        # An unknown (level, type) cmsg — not IP_TOS — must not alter the
        # datagram's DSCP (the default 0 from an unset IP_TOS option).
        self.assertEqual(
            s.sendmsg([b"x"], [(0xFFFF, 0xFFFF, b"\x10")]),
            1,
            msg="sendmsg() must accept an unknown cmsg 3-tuple and send the payload regardless.",
        )
        self.assertEqual(
            captured["ip__dscp"],
            0,
            msg="An unknown cmsg must not change the outbound DSCP.",
        )

    def test__udp_socket__sendmsg_rejects_malformed_ancdata(self) -> None:
        """
        Ensure sendmsg() rejects an ancillary-data entry that is not a
        '(cmsg_level, cmsg_type, cmsg_data)' 3-tuple with a TypeError,
        matching the stdlib structural contract.

        Reference: socket(7) sendmsg (ancillary-data structure).
        """

        s = self._connected_socket()

        bad_ancdata: list[Any] = [(1, 2)]
        with self.assertRaises(TypeError):
            s.sendmsg([b"x"], bad_ancdata)


class TestUdpSocketReceive(_UdpSocketTestCase):
    """
    The 'UdpSocket.recv' / 'UdpSocket.recvfrom' / 'process_udp_packet'
    tests.
    """

    def _make_md(self, data: bytes = b"payload") -> UdpMetadata:
        """
        Build a canonical IPv4 'UdpMetadata' envelope with the given
        payload.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(data),
        )

    def test__udp_socket__process_udp_packet_enqueues(self) -> None:
        """
        Ensure 'process_udp_packet' appends the envelope and releases
        the RX semaphore exactly once per call.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            1,
            msg="process_udp_packet must enqueue exactly one metadata entry.",
        )

    def test__udp_socket__so_rcvbuf_drops_datagram_over_cap(self) -> None:
        """
        Ensure that once 'SO_RCVBUF' is set, an inbound datagram whose
        payload would push the queued receive bytes past the cap is
        dropped rather than enqueued, mirroring the Linux receive-buffer
        overflow drop.

        Reference: RFC 1122 §4.2.2.16 (receive-buffer bound).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        # Cap admits two 7-byte payloads (14) but not a third (21 > 20).
        s.setsockopt(SOL_SOCKET, SO_RCVBUF, 20)
        s.process_udp_packet(self._make_md())
        s.process_udp_packet(self._make_md())
        s.process_udp_packet(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            2,
            msg="A datagram over the SO_RCVBUF cap must be dropped, not enqueued.",
        )

    def test__udp_socket__so_rcvbuf_admits_up_to_cap(self) -> None:
        """
        Ensure datagrams whose cumulative payload stays within the
        'SO_RCVBUF' cap are all admitted (the cap bounds, it does not
        reject at-or-below the limit).

        Reference: RFC 1122 §4.2.2.16 (receive-buffer bound).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_RCVBUF, 14)
        s.process_udp_packet(self._make_md())
        s.process_udp_packet(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            2,
            msg="Datagrams within the SO_RCVBUF cap must all be admitted.",
        )

    def test__udp_socket__so_rcvbuf_unset_is_unbounded(self) -> None:
        """
        Ensure that with 'SO_RCVBUF' unset the receive queue is
        unbounded (no default cap), so setting the option is what makes
        it bite — existing workloads are unaffected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        for _ in range(50):
            s.process_udp_packet(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            50,
            msg="With SO_RCVBUF unset every datagram must be enqueued.",
        )

    def test__udp_socket__recv_returns_payload(self) -> None:
        """
        Ensure recv() dequeues a single queued packet and returns its
        payload as 'bytes'.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        self.assertEqual(
            s.recv(),
            b"payload",
            msg="recv() must return the queued payload as bytes.",
        )

    def test__udp_socket__recv_timeout_raises(self) -> None:
        """
        Ensure recv() with a finite timeout raises 'TimeoutError' when
        no packet arrives.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(TimeoutError):
            s.recv(timeout=0.01)

    def test__udp_socket__recv_unreachable_raises(self) -> None:
        """
        Ensure recv() on a socket flagged unreachable raises
        'ConnectionRefusedError' and clears the flag.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.notify_unreachable()
        with self.assertRaises(ConnectionRefusedError):
            s.recv()
        self.assertFalse(
            s._unreachable,
            msg="recv() must clear the unreachable flag after translating it into ConnectionRefusedError.",
        )

    def test__udp_socket__recv_mv_returns_memoryview(self) -> None:
        """
        Ensure recv__mv() returns the underlying memoryview without
        copying through 'bytes'. Downstream parsers rely on the
        zero-copy behavior.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        data = s.recv__mv()
        self.assertIsInstance(
            data,
            memoryview,
            msg="recv__mv() must return a memoryview (zero-copy).",
        )
        self.assertEqual(
            bytes(data),
            b"payload",
            msg="recv__mv() must return the queued payload.",
        )

    def test__udp_socket__recvfrom_returns_payload_and_addr(self) -> None:
        """
        Ensure recvfrom() returns a (bytes, (str_ip, port)) tuple
        extracted from the metadata's remote-side fields.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        data, addr = s.recvfrom()
        self.assertEqual(data, b"payload", msg="recvfrom() must return the queued payload as bytes.")
        self.assertEqual(
            addr,
            ("10.0.0.2", 5678),
            msg="recvfrom() must return (remote_ip_str, remote_port) as the second tuple element.",
        )

    def test__udp_socket__recvfrom_timeout_raises(self) -> None:
        """
        Ensure recvfrom() with a finite timeout raises 'TimeoutError'
        when no packet arrives.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(TimeoutError):
            s.recvfrom(timeout=0.01)

    def _make_md_with_tos(self, tos: int = 0xC2) -> UdpMetadata:
        """
        Build a canonical IPv4 'UdpMetadata' envelope carrying a
        non-zero TOS byte. Default 0xC2 == DSCP=48 / ECN=2
        (ECT(0)), matching the IP_TOS tests.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(b"payload"),
            ip__tos=tos,
        )

    def _make_md_ip6_with_tclass(self, tclass: int = 0xC2) -> UdpMetadata:
        """
        Build a canonical IPv6 'UdpMetadata' envelope carrying a
        non-zero Traffic Class byte.
        """

        from net_addr import Ip6Address

        return UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(b"payload"),
            ip__tos=tclass,
        )

    def _make_md_with_options(self) -> UdpMetadata:
        """
        Build a canonical IPv4 'UdpMetadata' envelope carrying a
        Router Alert IPv4 option (RFC 2113) on the inbound datagram.
        """

        from net_proto.protocols.ip4.options.ip4__option__router_alert import (
            Ip4OptionRouterAlert,
        )
        from net_proto.protocols.ip4.options.ip4__options import Ip4Options

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(b"payload"),
            ip4__options=Ip4Options(Ip4OptionRouterAlert()),
        )

    def test__udp_socket__recvmsg_returns_quadruple(self) -> None:
        """
        Ensure recvmsg() returns the four-element
        '(data, ancdata, msg_flags, address)' tuple matching the
        Python stdlib 'socket.recvmsg' shape.

        Reference: RFC 1122 §4.1.3.2 (UDP MUST pass IP options to
        the application layer).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.process_udp_packet(self._make_md())

        result = s.recvmsg()

        self.assertEqual(
            len(result),
            4,
            msg="recvmsg() must return a 4-tuple (data, ancdata, msg_flags, address).",
        )

    def test__udp_socket__recvmsg_ipv4_address_two_tuple(self) -> None:
        """
        Ensure recvmsg() returns a 2-tuple '(host, port)' as the
        address for IPv4 sockets, matching stdlib
        'socket.recvmsg' on AF_INET.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.process_udp_packet(self._make_md())

        _data, _ancdata, _flags, address = s.recvmsg()

        self.assertEqual(
            address,
            ("10.0.0.2", 5678),
            msg="recvmsg() on AF_INET must return a (host, port) 2-tuple.",
        )

    def test__udp_socket__recvmsg_ipv6_address_four_tuple(self) -> None:
        """
        Ensure recvmsg() returns a 4-tuple
        '(host, port, flowinfo, scope_id)' as the address for
        IPv6 sockets, matching stdlib 'socket.recvmsg' on
        AF_INET6.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip6Address

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)
        md = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(b"payload"),
        )
        s.process_udp_packet(md)

        _data, _ancdata, _flags, address = s.recvmsg()

        self.assertEqual(
            address,
            ("2001:db8::2", 5678, 0, 0),
            msg="recvmsg() on AF_INET6 must return a (host, port, flowinfo, scope_id) 4-tuple.",
        )

    def test__udp_socket__recvmsg_no_options_no_ancdata(self) -> None:
        """
        Ensure recvmsg() returns an empty ancdata list when the
        inbound datagram carries no IPv4 options, regardless of
        whether IP_RECVOPTS is set on the socket.

        Reference: RFC 1122 §4.1.3.2 (cmsg surface limited to
        options actually carried).
        """

        from pytcp.runtime.socket import IP_RECVOPTS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)
        s.process_udp_packet(self._make_md())

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            ancdata,
            [],
            msg="recvmsg() must return empty ancdata when the datagram carries no IPv4 options.",
        )

    def test__udp_socket__recvmsg_options_with_ip_recvopts_returns_cmsg(self) -> None:
        """
        Ensure recvmsg(ancbufsize > 0) returns an IP_OPTIONS cmsg
        carrying the raw IPv4 options block when 'IP_RECVOPTS' is
        set on the socket and the inbound datagram carried IPv4
        options. The cmsg shape is
        '(IPPROTO_IP, IP_OPTIONS, raw_bytes)'.

        Reference: RFC 1122 §4.1.3.2 (UDP MUST pass IP options to
        the application layer).
        """

        from pytcp.runtime.socket import IP_OPTIONS, IP_RECVOPTS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)
        s.process_udp_packet(self._make_md_with_options())

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            len(ancdata),
            1,
            msg="recvmsg(ancbufsize>0) on a datagram with IPv4 options must return one cmsg when IP_RECVOPTS=1.",
        )
        level, type_, value = ancdata[0]
        self.assertEqual(
            level,
            int(IPPROTO_IP),
            msg="IP_OPTIONS cmsg must use level=IPPROTO_IP.",
        )
        self.assertEqual(
            type_,
            int(IP_OPTIONS),
            msg="IP_OPTIONS cmsg must use type=IP_OPTIONS.",
        )
        # Router Alert option: kind=0x94, len=0x04, value=0x0000.
        self.assertEqual(
            value,
            b"\x94\x04\x00\x00",
            msg="IP_OPTIONS cmsg value must be the raw options block bytes.",
        )

    def test__udp_socket__recvmsg_options_without_ip_recvopts_no_cmsg(self) -> None:
        """
        Ensure recvmsg() returns empty ancdata when IP_RECVOPTS is
        not set on the socket, even if the inbound datagram
        carries IPv4 options. Mirrors Linux's per-socket gating —
        application must opt in to receive ancillary IP options.

        Reference: RFC 1122 §4.1.3.2 (IP_RECVOPTS gates the
        ancillary-data pass-through).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.process_udp_packet(self._make_md_with_options())

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            ancdata,
            [],
            msg="recvmsg() must return empty ancdata when IP_RECVOPTS is not set.",
        )

    def test__udp_socket__recvmsg_options_with_zero_ancbufsize_no_cmsg(self) -> None:
        """
        Ensure recvmsg(ancbufsize=0) returns empty ancdata even
        when IP_RECVOPTS=1 and the datagram carried IPv4
        options. The zero buffer size means the caller asked for
        no ancillary data; matches stdlib's default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import IP_RECVOPTS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)
        s.process_udp_packet(self._make_md_with_options())

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=0)

        self.assertEqual(
            ancdata,
            [],
            msg="recvmsg(ancbufsize=0) must return empty ancdata regardless of IP_RECVOPTS.",
        )

    def test__udp_socket__recvmsg_data_returned_as_bytes(self) -> None:
        """
        Ensure recvmsg() returns the data element as 'bytes' (not
        'memoryview'), matching stdlib 'socket.recvmsg'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.process_udp_packet(self._make_md(b"hello"))

        data, _ancdata, _flags, _address = s.recvmsg()

        self.assertIsInstance(
            data,
            bytes,
            msg="recvmsg() must return data as 'bytes', not memoryview.",
        )
        self.assertEqual(
            data,
            b"hello",
            msg="recvmsg() must return the queued payload as bytes.",
        )

    def test__udp_socket__recvmsg_ip_tos_with_recvtos_returns_cmsg(self) -> None:
        """
        Ensure recvmsg(ancbufsize > 0) returns an IP_TOS cmsg
        carrying the inbound datagram's TOS byte (one byte,
        matching Linux's 'ip(7)' wire shape) when 'IP_RECVTOS'
        is set on an AF_INET socket.

        Reference: RFC 1122 §4.1.4 (UDP MAY pass received TOS up
        to the application layer).
        """

        from pytcp.runtime.socket import IP_RECVTOS, IP_TOS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)
        s.process_udp_packet(self._make_md_with_tos(tos=0xC2))

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            len(ancdata),
            1,
            msg="recvmsg(ancbufsize>0) must surface one cmsg when IP_RECVTOS=1.",
        )
        self.assertEqual(
            ancdata[0],
            (int(IPPROTO_IP), int(IP_TOS), b"\xc2"),
            msg="IP_TOS cmsg must carry (IPPROTO_IP, IP_TOS, single-byte TOS).",
        )

    def test__udp_socket__recvmsg_ip_tos_without_recvtos_no_cmsg(self) -> None:
        """
        Ensure recvmsg() returns empty ancdata for the IP_TOS
        cmsg when 'IP_RECVTOS' is not set on the socket, even
        though the inbound datagram had a non-zero TOS byte.

        Reference: RFC 1122 §4.1.4 (IP_RECVTOS gates the
        ancillary-data pass-through).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.process_udp_packet(self._make_md_with_tos(tos=0xC2))

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when IP_RECVTOS is not set.",
        )

    def test__udp_socket__recvmsg_ip_tos_zero_byte_with_recvtos_returns_cmsg(self) -> None:
        """
        Ensure recvmsg() emits an IP_TOS cmsg with value b"\\x00"
        when 'IP_RECVTOS' is set and the inbound datagram
        carried TOS=0. The cmsg is unconditional once the
        per-socket flag is set; applications distinguish
        absence-of-option from zero-valued option by the cmsg
        presence.

        Reference: RFC 1122 §4.1.4 (TOS surface is per-datagram).
        """

        from pytcp.runtime.socket import IP_RECVTOS, IP_TOS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)
        s.process_udp_packet(self._make_md_with_tos(tos=0))

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            ancdata,
            [(int(IPPROTO_IP), int(IP_TOS), b"\x00")],
            msg="IP_TOS cmsg must be emitted with b'\\x00' for a zero-TOS datagram when IP_RECVTOS=1.",
        )

    def test__udp_socket__recvmsg_ipv6_tclass_with_recvtclass_returns_cmsg(self) -> None:
        """
        Ensure recvmsg(ancbufsize > 0) on an AF_INET6 socket
        returns an IPV6_TCLASS cmsg carrying the inbound
        datagram's Traffic Class byte as a 4-byte big-endian
        integer (matching Linux's 'ipv6(7)' wire shape) when
        'IPV6_RECVTCLASS' is set.

        Reference: RFC 3542 §6.5 (IPv6 Traffic Class ancillary
        data uses sizeof(int)).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_RECVTCLASS, IPV6_TCLASS

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 1)
        s.process_udp_packet(self._make_md_ip6_with_tclass(tclass=0xC2))

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            len(ancdata),
            1,
            msg="recvmsg(ancbufsize>0) must surface one cmsg when IPV6_RECVTCLASS=1.",
        )
        level, type_, value = ancdata[0]
        self.assertEqual(
            (level, type_),
            (int(IPPROTO_IPV6), int(IPV6_TCLASS)),
            msg="IPV6_TCLASS cmsg must use (IPPROTO_IPV6, IPV6_TCLASS).",
        )
        self.assertEqual(
            int.from_bytes(value, "big"),
            0xC2,
            msg="IPV6_TCLASS cmsg value must be a 4-byte big-endian int matching the Traffic Class byte.",
        )

    def test__udp_socket__recvmsg_ipv6_tclass_without_recvtclass_no_cmsg(self) -> None:
        """
        Ensure recvmsg() on an AF_INET6 socket returns empty
        ancdata when 'IPV6_RECVTCLASS' is not set, even though
        the inbound datagram carried a non-zero Traffic Class
        byte.

        Reference: RFC 3542 §6.5 (per-socket opt-in for
        IPV6_TCLASS ancillary data).
        """

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)
        s.process_udp_packet(self._make_md_ip6_with_tclass(tclass=0xC2))

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=256)

        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when IPV6_RECVTCLASS is not set.",
        )

    def test__udp_socket__recvmsg_ip_tos_zero_ancbufsize_no_cmsg(self) -> None:
        """
        Ensure recvmsg(ancbufsize=0) returns empty ancdata even
        when 'IP_RECVTOS' is set, mirroring the zero-buffer
        semantics already enforced for IP_OPTIONS.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import IP_RECVTOS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)
        s.process_udp_packet(self._make_md_with_tos(tos=0xC2))

        _data, ancdata, _flags, _address = s.recvmsg(ancbufsize=0)

        self.assertEqual(
            ancdata,
            [],
            msg="recvmsg(ancbufsize=0) must return empty ancdata regardless of IP_RECVTOS.",
        )

    def test__udp_socket__recvmsg_timeout_raises(self) -> None:
        """
        Ensure recvmsg() with a finite timeout raises
        'TimeoutError' when no packet arrives, matching
        recv / recvfrom behaviour.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        with self.assertRaises(TimeoutError):
            s.recvmsg(timeout=0.01)


class TestUdpSocketClose(_UdpSocketTestCase):
    """
    The 'UdpSocket.close' teardown tests.
    """

    def test__udp_socket__close_removes_socket_from_registry(self) -> None:
        """
        Ensure close() removes the socket from 'stack.sockets' so
        subsequent packets cannot be routed to it.

        Reference: RFC 768 (UDP user interface).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="Precondition: bind() must register the socket.",
        )

        s.close()

        self.assertNotIn(
            s.socket_id,
            self._sockets,
            msg="close() must unregister the socket from stack.sockets.",
        )


class TestUdpSocketFileno(_UdpSocketTestCase):
    """
    The 'UdpSocket.fileno' / read-readiness signal-and-drain tests.
    """

    def _make_md(self, data: bytes = b"payload") -> UdpMetadata:
        """
        Build a canonical IPv4 UDP envelope for the read-side path.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(data),
        )

    @override
    def setUp(self) -> None:
        """
        Build a fresh UDP socket. 'tearDown' closes it before the
        parent fixture stops the 'log' patch so the close-time log
        line stays suppressed.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET4)

    @override
    def tearDown(self) -> None:
        """
        Close the socket while the 'log' patch is still active, then
        let the parent tear down the stack stubs.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__udp_socket__fileno_returns_non_negative_int(self) -> None:
        """
        Ensure 'fileno()' on a UDP socket returns a non-negative
        integer file descriptor for selector / poll consumption.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()

        self.assertIsInstance(
            fd,
            int,
            msg="UdpSocket.fileno() must return an int.",
        )
        self.assertGreaterEqual(
            fd,
            0,
            msg="UdpSocket.fileno() must return a non-negative fd.",
        )

    def test__udp_socket__fileno_initially_not_select_ready(self) -> None:
        """
        Ensure a freshly-constructed UDP socket reports as not
        readable until a packet has been delivered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="A fresh UdpSocket must not be select-readable.",
        )

    def test__udp_socket__fileno_select_ready_after_packet_arrives(self) -> None:
        """
        Ensure 'process_udp_packet' transitions the fd into the
        select-readable state — selectors driven by an event-loop
        framework rely on this to deliver wakeups.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md())

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="process_udp_packet must mark the fd as select-readable.",
        )

    def test__udp_socket__fileno_drained_after_recv_consumes_last_packet(self) -> None:
        """
        Ensure 'recv()' returns the fd to the not-readable state
        once the last queued datagram has been consumed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md())
        self._socket.recv()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="recv() draining the last packet must clear the readable bit.",
        )

    def test__udp_socket__fileno_remains_select_ready_with_pending_packets(self) -> None:
        """
        Ensure a partial drain (one of several queued packets
        consumed) leaves the fd select-readable so the next
        selector tick still wakes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"first"))
        self._socket.process_udp_packet(self._make_md(b"second"))
        self._socket.recv()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="recv() draining one of several packets must leave the fd readable.",
        )

    def test__udp_socket__recvfrom_drains_fileno_when_queue_empties(self) -> None:
        """
        Ensure 'recvfrom()' parallels 'recv()' in clearing the fd's
        readable bit on consuming the last datagram.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md())
        self._socket.recvfrom()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="recvfrom() draining the last packet must clear the readable bit.",
        )

    def test__udp_socket__close_closes_underlying_fd(self) -> None:
        """
        Ensure 'close()' tears down the eventfd backing 'fileno()'
        so the OS resource is reclaimed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()
        self._socket.close()

        with self.assertRaises(OSError) as context:
            fcntl.fcntl(fd, fcntl.F_GETFD)

        self.assertEqual(
            context.exception.errno,
            errno.EBADF,
            msg="close() must close the eventfd backing fileno() (EBADF on syscall).",
        )


class TestUdpSocketNonBlocking(_UdpSocketTestCase):
    """
    The 'UdpSocket.setblocking' non-blocking-recv tests.
    """

    def _make_md(self, data: bytes = b"payload") -> UdpMetadata:
        """
        Build a canonical IPv4 UDP envelope.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(data),
        )

    @override
    def setUp(self) -> None:
        """
        Build a non-blocking UDP socket. tearDown closes it before
        the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET4)
        self._socket.setblocking(False)

    @override
    def tearDown(self) -> None:
        """
        Close the socket before the parent tears down patches.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__udp_socket__recv_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recv()' on a non-blocking socket with an empty queue
        raises 'BlockingIOError' carrying 'errno.EAGAIN', matching
        the POSIX 'recv(2)' contract for a 'O_NONBLOCK' fd with no
        data ready.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recv()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recv() with no data must raise BlockingIOError(EAGAIN).",
        )

    def test__udp_socket__recvfrom_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recvfrom()' parallels 'recv()' in raising
        'BlockingIOError(EAGAIN)' on a non-blocking socket with an
        empty queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recvfrom()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recvfrom() with no data must raise BlockingIOError(EAGAIN).",
        )

    def test__udp_socket__recv_returns_data_when_non_blocking_and_packet_queued(self) -> None:
        """
        Ensure 'recv()' on a non-blocking socket returns the queued
        payload immediately when one is available — non-blocking
        mode only changes the empty-queue behavior.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"payload"))

        self.assertEqual(
            self._socket.recv(),
            b"payload",
            msg="Non-blocking recv() with a queued packet must return its payload.",
        )

    def test__udp_socket__recv_per_call_timeout_overrides_non_blocking(self) -> None:
        """
        Ensure an explicit 'timeout=' parameter takes precedence over
        the 'setblocking(False)' flag — the per-call argument wins,
        matching CPython's 'socket.recv(...)' semantics where a
        per-call timeout supersedes the persistent flag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TimeoutError):
            self._socket.recv(timeout=0.01)

    def test__udp_socket__recv_blocking_mode_unchanged_by_default(self) -> None:
        """
        Ensure a default-mode (blocking=True) socket with a finite
        per-call timeout still raises 'TimeoutError' rather than
        'BlockingIOError' — the blocking-flag plumbing must not
        regress the existing timeout behavior.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(TimeoutError):
            s.recv(timeout=0.01)


class TestUdpSocketRecvBufsize(_UdpSocketTestCase):
    """
    The 'UdpSocket.recv' / 'recvfrom' bufsize-truncation tests.
    """

    def _make_md(self, data: bytes) -> UdpMetadata:
        """
        Build a canonical IPv4 UDP envelope carrying the supplied
        payload.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(data),
        )

    @override
    def setUp(self) -> None:
        """
        Build a UDP socket; tearDown closes it before the parent
        fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET4)

    @override
    def tearDown(self) -> None:
        """
        Close the socket before the parent tears down patches.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__udp_socket__recv_truncates_oversized_datagram_to_bufsize(self) -> None:
        """
        Ensure 'recv(bufsize)' returns at most 'bufsize' bytes when
        the queued datagram exceeds it; the datagram remainder is
        silently discarded per POSIX 'recv(2)' semantics on UDP.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"abcdefghij"))

        self.assertEqual(
            self._socket.recv(bufsize=4),
            b"abcd",
            msg="recv(bufsize=4) on a 10-byte datagram must return the first 4 bytes only.",
        )

    def test__udp_socket__recv_with_bufsize_returns_full_when_smaller(self) -> None:
        """
        Ensure 'recv(bufsize)' returns the full datagram unchanged
        when the datagram is smaller than 'bufsize' — bufsize is a
        ceiling, not a floor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"hi"))

        self.assertEqual(
            self._socket.recv(bufsize=1024),
            b"hi",
            msg="recv(bufsize=1024) on a 2-byte datagram must return the full payload.",
        )

    def test__udp_socket__recv_with_bufsize_none_returns_full_payload(self) -> None:
        """
        Ensure 'recv()' with no 'bufsize' argument (the default
        'None') returns the complete datagram — preserves the
        existing call-shape that does not pass 'bufsize'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = b"x" * 1500
        self._socket.process_udp_packet(self._make_md(payload))

        self.assertEqual(
            self._socket.recv(),
            payload,
            msg="recv() without bufsize must return the full datagram.",
        )

    def test__udp_socket__recv_with_bufsize_zero_returns_empty(self) -> None:
        """
        Ensure 'recv(bufsize=0)' returns 'b""' and consumes the
        queued datagram per POSIX UDP recv semantics — bufsize of
        zero is a valid request that yields no bytes but still
        pops the datagram off the queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"payload"))

        self.assertEqual(
            self._socket.recv(bufsize=0),
            b"",
            msg="recv(bufsize=0) must return empty bytes.",
        )
        self.assertEqual(
            len(self._socket._packet_rx_md),
            0,
            msg="recv(bufsize=0) must still consume the queued datagram.",
        )

    def test__udp_socket__recvfrom_truncates_oversized_datagram_to_bufsize(self) -> None:
        """
        Ensure 'recvfrom(bufsize)' parallels 'recv(bufsize)' by
        truncating an oversized datagram while still returning the
        sender's address tuple.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"abcdefghij"))

        data, addr = self._socket.recvfrom(bufsize=3)

        self.assertEqual(
            data,
            b"abc",
            msg="recvfrom(bufsize=3) must truncate the payload to 3 bytes.",
        )
        self.assertEqual(
            addr,
            ("10.0.0.2", 5678),
            msg="recvfrom(bufsize=3) must still return the sender's (ip, port).",
        )

    def test__udp_socket__recv_mv_with_bufsize_truncates_memoryview(self) -> None:
        """
        Ensure 'recv__mv(bufsize)' returns a memoryview limited to
        'bufsize' bytes — the zero-copy variant honors the same
        truncation contract as 'recv()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"abcdefghij"))

        mv = self._socket.recv__mv(bufsize=5)

        self.assertEqual(
            len(mv),
            5,
            msg="recv__mv(bufsize=5) must return a 5-byte memoryview.",
        )
        self.assertEqual(
            bytes(mv),
            b"abcde",
            msg="recv__mv(bufsize=5) must contain the first 5 datagram bytes.",
        )

    def test__udp_socket__recvfrom_mv_with_bufsize_truncates_memoryview(self) -> None:
        """
        Ensure 'recvfrom__mv(bufsize)' truncates the memoryview to
        'bufsize' bytes while still returning the sender tuple.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_udp_packet(self._make_md(b"abcdefghij"))

        mv, addr = self._socket.recvfrom__mv(bufsize=2)

        self.assertEqual(
            bytes(mv),
            b"ab",
            msg="recvfrom__mv(bufsize=2) must contain the first 2 datagram bytes.",
        )
        self.assertEqual(
            addr,
            ("10.0.0.2", 5678),
            msg="recvfrom__mv(bufsize=2) must still return the sender's (ip, port).",
        )


class TestUdpSocketSolSocketOptions(_UdpSocketTestCase):
    """
    The 'UdpSocket' SOL_SOCKET-level setsockopt / getsockopt tests.
    """

    def test__udp_socket__so_reuseaddr_round_trip(self) -> None:
        """
        Ensure setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) +
        getsockopt round-trips as 1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_REUSEADDR),
            1,
            msg="SO_REUSEADDR must round-trip via setsockopt/getsockopt.",
        )

    def test__udp_socket__so_reuseport_round_trip(self) -> None:
        """
        Ensure setsockopt(SOL_SOCKET, SO_REUSEPORT, 1) + getsockopt
        round-trips as 1, and the default reads as 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_REUSEPORT),
            0,
            msg="SO_REUSEPORT must default to 0.",
        )

        s.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_REUSEPORT),
            1,
            msg="SO_REUSEPORT must round-trip via setsockopt/getsockopt.",
        )

    def test__udp_socket__so_reuseaddr_bypasses_address_in_use_check(self) -> None:
        """
        Ensure 'bind()' on a SO_REUSEADDR-set socket succeeds even
        when the (addr, port) tuple is already registered, mirroring
        Linux's 'setsockopt(SO_REUSEADDR)' semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(first.close)
        first.bind(("10.0.0.1", 8080))

        second = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(second.close)
        second.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        second.bind(("10.0.0.1", 8080))  # must not raise.

    def test__udp_socket__so_reuseport_allows_duplicate_bind_into_cohort(self) -> None:
        """
        Ensure two SO_REUSEPORT sockets bind the identical (ip, port)
        and both land in the registry cohort (neither clobbers the
        other).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(first.close)
        first.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        first.bind(("10.0.0.1", 8080))

        second = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(second.close)
        second.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        second.bind(("10.0.0.1", 8080))  # must not raise.

        self.assertCountEqual(
            self._sockets.values(),
            [first, second],
            msg="both SO_REUSEPORT sockets must coexist in the registry cohort.",
        )

    def test__udp_socket__so_reuseport_mixed_with_plain_raises(self) -> None:
        """
        Ensure a SO_REUSEPORT bind conflicts with a plain socket
        already bound to the same (ip, port) — the group rule requires
        every member to set the flag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(first.close)
        first.bind(("10.0.0.1", 8080))  # plain, no SO_REUSEPORT.

        second = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(second.close)
        second.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)

        with self.assertRaises(OSError) as ctx:
            second.bind(("10.0.0.1", 8080))

        self.assertEqual(
            ctx.exception.errno,
            errno.EADDRINUSE,
            msg="SO_REUSEPORT must not join a cohort with a non-REUSEPORT socket.",
        )

    def test__udp_socket__so_rcvtimeo_supplies_recv_default_timeout(self) -> None:
        """
        Ensure setsockopt(SOL_SOCKET, SO_RCVTIMEO, N) makes a
        subsequent 'recv()' (with no per-call timeout) raise
        'TimeoutError' after N seconds elapsed — Linux 'SO_RCVTIMEO'
        contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_RCVTIMEO, 1)  # internal: 1 second

        # Use a small float manually to keep the test fast.
        s._so_rcvtimeo = 0.01

        with self.assertRaises(TimeoutError):
            s.recv()

    def test__udp_socket__so_broadcast_round_trip(self) -> None:
        """
        Ensure setsockopt(SOL_SOCKET, SO_BROADCAST, 1) round-trips.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_BROADCAST),
            1,
            msg="SO_BROADCAST must round-trip via setsockopt/getsockopt.",
        )

    def test__udp_socket__so_sndbuf_so_rcvbuf_round_trip(self) -> None:
        """
        Ensure SO_SNDBUF / SO_RCVBUF integer values round-trip via
        setsockopt / getsockopt. Behavioral enforcement of these
        caps is deferred — apps that probe for support via the
        round-trip succeed today.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_SNDBUF, 8192)
        s.setsockopt(SOL_SOCKET, SO_RCVBUF, 16384)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_SNDBUF),
            8192,
            msg="SO_SNDBUF must round-trip the configured value.",
        )
        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_RCVBUF),
            16384,
            msg="SO_RCVBUF must round-trip the configured value.",
        )

    def test__udp_socket__so_rcvbuf_getsockopt_reports_default_when_unset(self) -> None:
        """
        Ensure getsockopt(SO_RCVBUF) reports the effective default
        receive-buffer size on a socket that never set it, rather
        than 0 — Linux getsockopt never reports a zero buffer.

        Reference: Linux socket(7) SO_RCVBUF (getsockopt returns the
        effective buffer size, not 0).
        """

        from pytcp.runtime.socket import SOCKET__SO_RCVBUF__DEFAULT

        s = UdpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_RCVBUF),
            SOCKET__SO_RCVBUF__DEFAULT,
            msg="An unset SO_RCVBUF must getsockopt as the effective default, not 0.",
        )

    def test__udp_socket__ip_ttl_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_TTL, 32) round-trips and
        the per-socket TTL override is forwarded into
        'send_udp_packet' via the 'ip__ttl' kwarg.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import IP_TTL, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_TTL, 32)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_TTL),
            32,
            msg="IP_TTL must round-trip via setsockopt/getsockopt.",
        )

    def test__udp_socket__ip_ttl_threads_into_send_udp_packet(self) -> None:
        """
        Ensure a non-default IP_TTL set on a UDP socket appears as
        the 'ip__ttl' kwarg on 'send_udp_packet'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import IP_TTL, IPPROTO_IP

        captured: list[dict[str, Any]] = []

        original_send = self._handler.send_udp_packet

        def _capture_send(**kw: object) -> object:
            captured.append(dict(kw))
            return original_send(**kw)

        self._handler.send_udp_packet = _capture_send

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_TTL, 32)
        s.bind(("10.0.0.1", 5555))
        with patch(
            "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.sendto(b"data", ("10.0.0.5", 9999))

        self.assertEqual(
            captured[0].get("ip__ttl"),
            32,
            msg="setsockopt(IP_TTL, 32) must thread into send_udp_packet's ip__ttl kwarg.",
        )

    def test__udp_socket__ip_tos_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_TOS) stores an 8-bit DSCP+ECN
        value with the low 2 bits exposed as ECN to send_udp_packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import IP_TOS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_TOS, 0xC2)  # DSCP=48, ECN=2 (ECT(0))

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_TOS),
            0xC2,
            msg="IP_TOS must round-trip the full 8-bit DSCP+ECN value.",
        )

    def test__udp_socket__ip_mtu_returns_cached_pmtu_on_connected_ipv4(self) -> None:
        """
        Ensure getsockopt(IPPROTO_IP, IP_MTU) on a connected IPv4
        UDP socket returns the cached Path-MTU for the remote
        address from 'stack.pmtu_cache'.

        Reference: RFC 1122 §3.4 (GET_MAXSIZES).
        Reference: RFC 1191 §3 (Path-MTU discovery surfacing).
        """

        from pytcp import stack as _stack
        from pytcp.runtime.socket import IP_MTU, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        remote = Ip4Address("10.0.0.5")
        s._remote_ip_address = remote
        s._remote_port = 1234

        _stack.pmtu_cache[remote] = 1400
        self.addCleanup(_stack.pmtu_cache.pop, remote, None)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_MTU),
            1400,
            msg="IP_MTU must return the cached PMTU for a connected IPv4 socket.",
        )

    def test__udp_socket__ip_mtu_falls_back_to_egress_interface_mtu(self) -> None:
        """
        Ensure getsockopt(IPPROTO_IP, IP_MTU) returns the egress
        interface's link MTU ('stack.egress_interface_mtu()') when
        'stack.pmtu_cache' has no entry for the connected remote —
        Linux's same per-destination link-MTU fallback.

        Reference: RFC 1122 §3.4 (GET_MAXSIZES fallback to link MTU).
        """

        from pytcp import stack as _stack
        from pytcp.runtime.socket import IP_MTU, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s._remote_ip_address = Ip4Address("10.0.0.99")
        s._remote_port = 5678

        with patch.object(_stack, "egress_interface_mtu", return_value=1500):
            self.assertEqual(
                s.getsockopt(IPPROTO_IP, IP_MTU),
                1500,
                msg="IP_MTU must fall back to the egress interface MTU when no PMTU is cached.",
            )

    def test__udp_socket__ip_mtu_unconnected_raises_enotconn(self) -> None:
        """
        Ensure getsockopt(IPPROTO_IP, IP_MTU) on an unconnected
        socket raises OSError(ENOTCONN). The MTU surface is
        defined per-destination; without a destination there is
        no meaningful value to return.

        Reference: Linux 'ip(7)' (IP_MTU returns ENOTCONN when
        the socket has no peer).
        """

        import errno

        from pytcp.runtime.socket import IP_MTU, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as ctx:
            s.getsockopt(IPPROTO_IP, IP_MTU)

        self.assertEqual(
            ctx.exception.errno,
            errno.ENOTCONN,
            msg="IP_MTU on an unconnected socket must raise OSError(ENOTCONN).",
        )

    def test__udp_socket__ip_mtu_setsockopt_rejected(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_MTU, ...) raises
        OSError(ENOPROTOOPT). The IP_MTU option is getsockopt-
        only — Linux rejects writes the same way.

        Reference: Linux 'ip(7)' (IP_MTU is a read-only socket
        option).
        """

        import errno

        from pytcp.runtime.socket import IP_MTU, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as ctx:
            s.setsockopt(IPPROTO_IP, IP_MTU, 1500)

        self.assertEqual(
            ctx.exception.errno,
            errno.ENOPROTOOPT,
            msg="setsockopt on IP_MTU must raise OSError(ENOPROTOOPT) — read-only.",
        )

    def test__udp_socket__ipv6_mtu_returns_cached_pmtu_on_connected_ipv6(self) -> None:
        """
        Ensure getsockopt(IPPROTO_IPV6, IPV6_MTU) on a connected
        IPv6 UDP socket returns the cached Path-MTU for the
        remote address from 'stack.pmtu_cache'.

        Reference: RFC 1122 §3.4 (GET_MAXSIZES, IPv6 parallel).
        Reference: RFC 8201 §4 (IPv6 PMTUD surfacing).
        """

        from net_addr import Ip6Address
        from pytcp import stack as _stack
        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_MTU

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)
        remote = Ip6Address("2001:db8::5")
        s._remote_ip_address = remote
        s._remote_port = 1234

        _stack.pmtu_cache[remote] = 1280
        self.addCleanup(_stack.pmtu_cache.pop, remote, None)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_MTU),
            1280,
            msg="IPV6_MTU must return the cached PMTU for a connected IPv6 socket.",
        )

    def test__udp_socket__ipv6_mtu_unconnected_raises_enotconn(self) -> None:
        """
        Ensure getsockopt(IPPROTO_IPV6, IPV6_MTU) on an
        unconnected IPv6 socket raises OSError(ENOTCONN).

        Reference: Linux 'ipv6(7)' (IPV6_MTU returns ENOTCONN
        when the socket has no peer).
        """

        import errno

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_MTU

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as ctx:
            s.getsockopt(IPPROTO_IPV6, IPV6_MTU)

        self.assertEqual(
            ctx.exception.errno,
            errno.ENOTCONN,
            msg="IPV6_MTU on an unconnected socket must raise OSError(ENOTCONN).",
        )

    def test__udp_socket__ip_recverr_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_RECVERR, 1) toggles the
        per-socket flag that gates ICMP-error queue population
        for recvmsg(MSG_ERRQUEUE), and getsockopt returns the
        stored value.

        Reference: RFC 1122 §4.1.3.3 (UDP MUST pass ICMP errors
        up to the application).
        """

        from pytcp.runtime.socket import IP_RECVERR, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        self.assertEqual(s.getsockopt(IPPROTO_IP, IP_RECVERR), 0)
        s.setsockopt(IPPROTO_IP, IP_RECVERR, 1)
        self.assertEqual(s.getsockopt(IPPROTO_IP, IP_RECVERR), 1)
        s.setsockopt(IPPROTO_IP, IP_RECVERR, 0)
        self.assertEqual(s.getsockopt(IPPROTO_IP, IP_RECVERR), 0)

    def test__udp_socket__ipv6_recverr_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IPV6, IPV6_RECVERR, 1) toggles
        the per-socket flag for IPv6 error-queue population.

        Reference: RFC 1122 §4.1.3.3 (pass ICMP errors up; IPv6
        parallel surface).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_RECVERR

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)

        self.assertEqual(s.getsockopt(IPPROTO_IPV6, IPV6_RECVERR), 0)
        s.setsockopt(IPPROTO_IPV6, IPV6_RECVERR, 1)
        self.assertEqual(s.getsockopt(IPPROTO_IPV6, IPV6_RECVERR), 1)

    def test__udp_socket__notify_unreachable_enqueues_error_when_recverr_set(self) -> None:
        """
        Ensure notify_unreachable with full ICMP context appends
        an ErrorQueueEntry to the per-socket error queue when
        IP_RECVERR is set. The entry carries the
        ICMP→errno-mapped errno, ICMP origin / type / code,
        offender address, and embedded triggering datagram.

        Reference: RFC 1122 §4.1.3.3.
        """

        import errno as errno_mod

        from net_proto import Icmp4DestinationUnreachableCode, Icmp4Type
        from pytcp.runtime.socket import IP_RECVERR, IPPROTO_IP
        from pytcp.runtime.socket.error_queue import SoEeOrigin

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        s.notify_unreachable(
            icmp_origin=SoEeOrigin.ICMP,
            icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
            icmp_code=Icmp4DestinationUnreachableCode.PORT,
            offender_ip=Ip4Address("10.0.0.5"),
            embedded_datagram=b"triggering-datagram",
        )

        self.assertEqual(
            len(s._error_queue),
            1,
            msg="notify_unreachable must enqueue exactly one error when IP_RECVERR=1.",
        )
        entry = s._error_queue[0]
        self.assertEqual(entry.errno, errno_mod.ECONNREFUSED)
        self.assertEqual(entry.origin, SoEeOrigin.ICMP)
        self.assertEqual(entry.icmp_type, int(Icmp4Type.DESTINATION_UNREACHABLE))
        self.assertEqual(entry.icmp_code, int(Icmp4DestinationUnreachableCode.PORT))
        self.assertEqual(entry.offender_ip, Ip4Address("10.0.0.5"))
        self.assertEqual(entry.embedded_datagram, b"triggering-datagram")

    def test__udp_socket__notify_unreachable_no_enqueue_when_recverr_unset(self) -> None:
        """
        Ensure notify_unreachable does NOT enqueue when
        IP_RECVERR is unset. The legacy '_unreachable' flag
        still toggles so 'recv()' raises ConnectionRefusedError
        per the BSD single-error surface.

        Reference: RFC 1122 §4.1.3.3 (legacy
        ConnectionRefusedError path always wired).
        """

        from net_proto import Icmp4DestinationUnreachableCode, Icmp4Type
        from pytcp.runtime.socket.error_queue import SoEeOrigin

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        s.notify_unreachable(
            icmp_origin=SoEeOrigin.ICMP,
            icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
            icmp_code=Icmp4DestinationUnreachableCode.PORT,
            offender_ip=Ip4Address("10.0.0.5"),
            embedded_datagram=b"x",
        )

        self.assertEqual(len(s._error_queue), 0)
        self.assertTrue(s._unreachable)

    def test__udp_socket__notify_pmtu_enqueues_emsgsize_with_ee_info(self) -> None:
        """
        Ensure notify_pmtu appends an ErrorQueueEntry whose
        'errno' is EMSGSIZE and whose 'ee_info' carries the
        advertised next-hop MTU (Linux's IP_RECVERR
        sock_extended_err.ee_info convention).

        Reference: RFC 1191 §3 (Path-MTU discovery PMTU
        surfacing as IP_RECVERR EMSGSIZE).
        """

        import errno as errno_mod

        from net_proto import Icmp4DestinationUnreachableCode, Icmp4Type
        from pytcp.runtime.socket import IP_RECVERR, IPPROTO_IP
        from pytcp.runtime.socket.error_queue import SoEeOrigin

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        s.notify_pmtu(
            next_hop_mtu=1280,
            icmp_origin=SoEeOrigin.ICMP,
            icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
            icmp_code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
            offender_ip=Ip4Address("10.0.0.5"),
            embedded_datagram=b"big-datagram",
        )

        self.assertEqual(len(s._error_queue), 1)
        entry = s._error_queue[0]
        self.assertEqual(entry.errno, errno_mod.EMSGSIZE)
        self.assertEqual(entry.ee_info, 1280)

    def test__udp_socket__recvmsg_errqueue_returns_cmsg_with_embedded_datagram(self) -> None:
        """
        Ensure recvmsg(flags=MSG_ERRQUEUE) dequeues one
        ErrorQueueEntry and returns the 4-tuple
        '(embedded_datagram, [cmsg], MSG_ERRQUEUE, offender_addr)'
        matching Linux 'recvmsg(MSG_ERRQUEUE)' shape. The cmsg
        payload is a packed 'struct sock_extended_err' +
        offender sockaddr (16+16=32 bytes for IPv4).

        Reference: Linux 'ip(7)' (IP_RECVERR cmsg wire shape).
        """

        from net_proto import Icmp4DestinationUnreachableCode, Icmp4Type
        from pytcp.runtime.socket import (
            IP_RECVERR,
            IPPROTO_IP,
            MSG_ERRQUEUE,
        )
        from pytcp.runtime.socket.error_queue import SoEeOrigin

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        s.notify_unreachable(
            icmp_origin=SoEeOrigin.ICMP,
            icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
            icmp_code=Icmp4DestinationUnreachableCode.PORT,
            offender_ip=Ip4Address("10.0.0.5"),
            embedded_datagram=b"the-triggering-packet",
        )

        data, ancdata, flags, address = s.recvmsg(ancbufsize=256, flags=MSG_ERRQUEUE)

        self.assertEqual(data, b"the-triggering-packet")
        self.assertEqual(flags, int(MSG_ERRQUEUE))
        self.assertEqual(address, ("10.0.0.5", 0))
        self.assertEqual(len(ancdata), 1)
        level, type_, value = ancdata[0]
        self.assertEqual(level, int(IPPROTO_IP))
        self.assertEqual(type_, int(IP_RECVERR))
        self.assertEqual(len(value), 32, msg="sock_extended_err (16) + sockaddr_in (16) = 32 bytes.")

    def test__udp_socket__recvmsg_errqueue_empty_raises(self) -> None:
        """
        Ensure recvmsg(flags=MSG_ERRQUEUE, timeout=0.01) on an
        empty error queue raises TimeoutError (or
        BlockingIOError on a non-blocking socket).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import MSG_ERRQUEUE

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(TimeoutError):
            s.recvmsg(ancbufsize=256, flags=MSG_ERRQUEUE, timeout=0.01)

    def test__udp_socket__error_queue_bounded_drops_oldest(self) -> None:
        """
        Ensure the per-socket error queue caps at
        ERROR_QUEUE__MAX_LEN entries (32) and drops the oldest
        entry on overflow (FIFO drop, deque(maxlen=) semantics).

        Reference: PyTCP error-queue cap (no RFC clause; Linux
        equivalent caps via 'sysctl_optmem_max' byte budget).
        """

        from net_proto import Icmp4DestinationUnreachableCode, Icmp4Type
        from pytcp.runtime.socket import IP_RECVERR, IPPROTO_IP
        from pytcp.runtime.socket.error_queue import ERROR_QUEUE__MAX_LEN, SoEeOrigin

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        for i in range(ERROR_QUEUE__MAX_LEN + 5):
            s.notify_unreachable(
                icmp_origin=SoEeOrigin.ICMP,
                icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
                icmp_code=Icmp4DestinationUnreachableCode.PORT,
                offender_ip=Ip4Address("10.0.0.5"),
                embedded_datagram=str(i).encode(),
            )

        self.assertEqual(len(s._error_queue), ERROR_QUEUE__MAX_LEN)
        # Oldest 5 entries (indices 0-4) dropped; the queue now
        # starts at index 5.
        self.assertEqual(s._error_queue[0].embedded_datagram, b"5")
        self.assertEqual(
            s._error_queue[-1].embedded_datagram,
            str(ERROR_QUEUE__MAX_LEN + 4).encode(),
        )

    def test__udp_socket__so_sndtimeo_round_trip(self) -> None:
        """
        Ensure SO_SNDTIMEO round-trips via setsockopt / getsockopt.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_SNDTIMEO, 5)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_SNDTIMEO),
            5,
            msg="SO_SNDTIMEO must round-trip the configured value.",
        )

    def test__udp_socket__ip_options_round_trip_empty(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_OPTIONS, b"") clears the
        per-socket IPv4 options block and getsockopt returns an
        empty bytes object. The empty-block default is what an
        unmodified socket reports.

        Reference: RFC 1122 §4.1.3.2 (UDP MUST pass IP options to
        the IP layer).
        """

        from pytcp.runtime.socket import IP_OPTIONS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_OPTIONS),
            b"",
            msg="Default IP_OPTIONS must be an empty bytes object.",
        )

        s.setsockopt(IPPROTO_IP, IP_OPTIONS, b"")

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_OPTIONS),
            b"",
            msg="Empty IP_OPTIONS must round-trip.",
        )

    def test__udp_socket__ip_options_round_trip_router_alert(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_OPTIONS, <router alert>)
        stores the bytes block and getsockopt returns it verbatim.
        The Router Alert option (RFC 2113) is exactly 4 bytes
        (kind=0x94, len=4, value=0x0000) and therefore needs no
        padding to align the IPv4 header to a 32-bit-word
        boundary.

        Reference: RFC 1122 §4.1.3.2 (application MUST be able to
        specify IP options to be sent).
        """

        from pytcp.runtime.socket import IP_OPTIONS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        router_alert_bytes = b"\x94\x04\x00\x00"

        s.setsockopt(IPPROTO_IP, IP_OPTIONS, router_alert_bytes)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_OPTIONS),
            router_alert_bytes,
            msg="IP_OPTIONS must round-trip the supplied bytes block verbatim.",
        )

    def test__udp_socket__ip_options_rejects_unaligned_block(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_OPTIONS, <unaligned>)
        raises OSError(EINVAL). The IPv4 header length is encoded
        in 32-bit words so the options block must be a multiple
        of 4 bytes; Linux's setsockopt enforces the same.

        Reference: RFC 791 §3.1 (IHL field counts 32-bit words).
        """

        import errno

        from pytcp.runtime.socket import IP_OPTIONS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as ctx:
            s.setsockopt(IPPROTO_IP, IP_OPTIONS, b"\x94\x04\x00")

        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="Unaligned IP_OPTIONS must raise EINVAL.",
        )

    def test__udp_socket__ip_options_rejects_oversize_block(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_OPTIONS, <>40 bytes>)
        raises OSError(EINVAL). The IPv4 header is 60 bytes
        maximum (IHL=15 32-bit words), so the options block is
        capped at 40 bytes.

        Reference: RFC 791 §3.1 (IHL maximum = 15 → 60 byte
        header → 40 byte options).
        """

        import errno

        from pytcp.runtime.socket import IP_OPTIONS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as ctx:
            s.setsockopt(IPPROTO_IP, IP_OPTIONS, b"\x01" * 44)

        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="Oversize IP_OPTIONS must raise EINVAL.",
        )

    def test__udp_socket__ip_options_rejects_malformed_block(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_OPTIONS, <malformed>)
        raises OSError(EINVAL). An option with length < 2 is
        wire-malformed; the parser's integrity check rejects it.

        Reference: RFC 791 §3.1 (TLV length-field semantics).
        """

        import errno

        from pytcp.runtime.socket import IP_OPTIONS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as ctx:
            # Option kind=0x83 (LSRR), length=0x01 (invalid; must be ≥ 2).
            s.setsockopt(IPPROTO_IP, IP_OPTIONS, b"\x83\x01\x00\x00")

        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="Malformed IP_OPTIONS must raise EINVAL.",
        )

    def test__udp_socket__ip_recvtos_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_RECVTOS, 1) toggles the
        per-socket flag that gates IP_TOS cmsg emission on
        recvmsg, and getsockopt returns the stored value.

        Reference: RFC 1122 §4.1.4 (UDP MAY pass received TOS up
        to the application layer).
        """

        from pytcp.runtime.socket import IP_RECVTOS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_RECVTOS),
            0,
            msg="Default IP_RECVTOS must be 0.",
        )

        s.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_RECVTOS),
            1,
            msg="IP_RECVTOS=1 must round-trip.",
        )

        s.setsockopt(IPPROTO_IP, IP_RECVTOS, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_RECVTOS),
            0,
            msg="IP_RECVTOS=0 must round-trip.",
        )

    def test__udp_socket__ipv6_recvtclass_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 1)
        toggles the per-socket flag that gates IPV6_TCLASS cmsg
        emission on recvmsg, and getsockopt returns the stored
        value.

        Reference: RFC 3542 §6.5 (IPv6 Traffic Class ancillary
        data).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_RECVTCLASS

        s = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(s.close)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS),
            0,
            msg="Default IPV6_RECVTCLASS must be 0.",
        )

        s.setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 1)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS),
            1,
            msg="IPV6_RECVTCLASS=1 must round-trip.",
        )

        s.setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS),
            0,
            msg="IPV6_RECVTCLASS=0 must round-trip.",
        )

    def test__udp_socket__ip_recvopts_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_IP, IP_RECVOPTS, 1) toggles the
        per-socket flag that gates IP_OPTIONS cmsg emission on
        recvmsg, and getsockopt returns the stored value.

        Reference: RFC 1122 §4.1.3.2 (UDP MUST pass received IP
        options to the application layer).
        """

        from pytcp.runtime.socket import IP_RECVOPTS, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_RECVOPTS),
            0,
            msg="Default IP_RECVOPTS must be 0.",
        )

        s.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_RECVOPTS),
            1,
            msg="IP_RECVOPTS=1 must round-trip.",
        )

        s.setsockopt(IPPROTO_IP, IP_RECVOPTS, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_RECVOPTS),
            0,
            msg="IP_RECVOPTS=0 must round-trip.",
        )


class TestUdpSocketSelectorIntegration(_UdpSocketTestCase):
    """
    The 'UdpSocket' + 'selectors.DefaultSelector' integration tests.
    """

    def _make_md(self, data: bytes = b"payload") -> UdpMetadata:
        """
        Build a canonical IPv4 UDP envelope.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(data),
        )

    @override
    def setUp(self) -> None:
        """
        Build a UDP socket; tearDown closes it before the parent
        fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET4)

    @override
    def tearDown(self) -> None:
        """
        Close the socket before the parent tears down patches.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__udp_socket__selectors_default_selector_event_read_lifecycle(self) -> None:
        """
        Ensure a 'selectors.DefaultSelector' driving the socket
        sees the EVENT_READ bit toggle on/off across the full
        deliver -> recv lifecycle. This is the core asyncio /
        trio compatibility contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import selectors

        sel = selectors.DefaultSelector()
        sel.register(self._socket, selectors.EVENT_READ, data="udp")
        self.addCleanup(sel.close)

        self.assertEqual(
            sel.select(timeout=0),
            [],
            msg="A fresh socket must not be reported readable by the selector.",
        )

        self._socket.process_udp_packet(self._make_md(b"hello"))
        events = sel.select(timeout=0)
        self.assertEqual(
            len(events),
            1,
            msg="An arrived datagram must wake the selector with one EVENT_READ entry.",
        )
        self.assertTrue(
            events[0][1] & selectors.EVENT_READ,
            msg="The selector entry must carry the EVENT_READ bit.",
        )

        self._socket.recv()

        self.assertEqual(
            sel.select(timeout=0),
            [],
            msg="After draining the queue, the selector must not report readable.",
        )

    def test__udp_socket__bind_twice_oserror_carries_einval_errno(self) -> None:
        """
        Ensure binding an already-bound socket raises 'OSError' with
        '.errno == errno.EINVAL' so apps can branch on the errno
        constant rather than parsing the message text.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.bind(("10.0.0.1", 8080))

        with self.assertRaises(OSError) as context:
            s.bind(("10.0.0.1", 8081))

        self.assertEqual(
            context.exception.errno,
            errno.EINVAL,
            msg="bind-twice OSError must carry errno=EINVAL.",
        )

    def test__udp_socket__bind_foreign_ip_oserror_carries_eaddrnotavail_errno(self) -> None:
        """
        Ensure binding to a non-stack-owned IP raises 'OSError' with
        '.errno == errno.EADDRNOTAVAIL'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))

        self.assertEqual(
            context.exception.errno,
            errno.EADDRNOTAVAIL,
            msg="foreign-IP bind OSError must carry errno=EADDRNOTAVAIL.",
        )

    def test__udp_socket__bind_address_in_use_oserror_carries_eaddrinuse_errno(self) -> None:
        """
        Ensure binding to a port already in use raises 'OSError'
        with '.errno == errno.EADDRINUSE'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(first.close)
        first.bind(("10.0.0.1", 8080))

        second = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(second.close)

        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))

        self.assertEqual(
            context.exception.errno,
            errno.EADDRINUSE,
            msg="address-in-use bind OSError must carry errno=EADDRINUSE.",
        )

    def test__udp_socket__send_no_destination_oserror_carries_edestaddrreq_errno(self) -> None:
        """
        Ensure 'send()' on a socket with no remote IP raises
        'OSError' with '.errno == errno.EDESTADDRREQ'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as context:
            s.send(b"data")

        self.assertEqual(
            context.exception.errno,
            errno.EDESTADDRREQ,
            msg="send-without-destination OSError must carry errno=EDESTADDRREQ.",
        )

    def test__udp_socket__recv_unreachable_carries_econnrefused_errno(self) -> None:
        """
        Ensure 'recv()' translation of an ICMP Unreachable raises
        'ConnectionRefusedError' with '.errno == errno.ECONNREFUSED'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(s.close)
        s.notify_unreachable()

        with self.assertRaises(ConnectionRefusedError) as context:
            s.recv()

        self.assertEqual(
            context.exception.errno,
            errno.ECONNREFUSED,
            msg="ICMP-Unreachable ConnectionRefusedError must carry errno=ECONNREFUSED.",
        )

    def test__udp_socket__select_select_event_write_is_always_ready(self) -> None:
        """
        Ensure 'select.select' reports the socket as immediately
        writable. PyTCP's tx buffer is unbounded today, so the
        write-readable bit is always asserted; matches the
        kernel-level eventfd "writable when counter < UINT64_MAX -
        1" behavior.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import select as _select

        _, wlist, _ = _select.select([], [self._socket], [], 0)

        self.assertEqual(
            wlist,
            [self._socket],
            msg="The socket fd must always be select-writable while tx buffer is unbounded.",
        )


class TestUdpSocketMulticastLoop(_UdpSocketTestCase):
    """
    IP_MULTICAST_LOOP / IPV6_MULTICAST_LOOP acceptance: PyTCP
    accepts the multicast-loopback flag for stdlib / portability
    parity (Linux never returns ENOPROTOOPT) and round-trips it
    through getsockopt, defaulting to the Linux value of 1.
    """

    def test__ip_multicast_loop_default_is_1(self) -> None:
        """
        Ensure IP_MULTICAST_LOOP reads back as 1 (Linux default)
        on a socket that never set it.

        Reference: Linux IP_MULTICAST_LOOP (default 1).
        """

        from pytcp.runtime.socket import IP_MULTICAST_LOOP, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_MULTICAST_LOOP),
            1,
            msg="IP_MULTICAST_LOOP must default to 1.",
        )

    def test__ip_multicast_loop_setsockopt_getsockopt_roundtrip(self) -> None:
        """
        Ensure IP_MULTICAST_LOOP accepts an int and getsockopt
        echoes it back — the common 'disable loopback' (0) intent
        is stored without raising ENOPROTOOPT.

        Reference: Linux IP_MULTICAST_LOOP (multicast loopback flag).
        """

        from pytcp.runtime.socket import IP_MULTICAST_LOOP, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)

        s.setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP, 0)
        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_MULTICAST_LOOP),
            0,
            msg="IP_MULTICAST_LOOP must round-trip 0.",
        )
        s.setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP, 1)
        self.assertEqual(
            s.getsockopt(IPPROTO_IP, IP_MULTICAST_LOOP),
            1,
            msg="IP_MULTICAST_LOOP must round-trip 1.",
        )

    def test__ip_multicast_loop_non_int_raises_einval(self) -> None:
        """
        Ensure IP_MULTICAST_LOOP rejects a non-int value with
        EINVAL.

        Reference: Linux IP_MULTICAST_LOOP (integer flag).
        """

        from pytcp.runtime.socket import IP_MULTICAST_LOOP, IPPROTO_IP

        s = UdpSocket(family=AddressFamily.INET4)

        with self.assertRaises(OSError) as ctx:
            s.setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP, b"\x00")
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="IP_MULTICAST_LOOP with a bytes value must raise EINVAL.",
        )

    def test__ipv6_multicast_loop_default_is_1(self) -> None:
        """
        Ensure IPV6_MULTICAST_LOOP reads back as 1 (Linux default)
        on a socket that never set it.

        Reference: Linux IPV6_MULTICAST_LOOP (default 1).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_MULTICAST_LOOP

        s = UdpSocket(family=AddressFamily.INET6)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP),
            1,
            msg="IPV6_MULTICAST_LOOP must default to 1.",
        )

    def test__ipv6_multicast_loop_setsockopt_getsockopt_roundtrip(self) -> None:
        """
        Ensure IPV6_MULTICAST_LOOP accepts an int and getsockopt
        echoes it back.

        Reference: Linux IPV6_MULTICAST_LOOP (multicast loopback flag).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_MULTICAST_LOOP

        s = UdpSocket(family=AddressFamily.INET6)

        s.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 0)
        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP),
            0,
            msg="IPV6_MULTICAST_LOOP must round-trip 0.",
        )
        s.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1)
        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP),
            1,
            msg="IPV6_MULTICAST_LOOP must round-trip 1.",
        )


class TestUdpSocketSoSndbuf(_UdpSocketTestCase):
    """
    The SO_SNDBUF / SO_SNDTIMEO send-buffer accounting tests. A
    per-socket outstanding-bytes counter (Linux 'sk_wmem_alloc') is
    charged when a datagram is queued and released via the
    TX-completion hook; a send that would exceed SO_SNDBUF blocks up
    to SO_SNDTIMEO or fails with EAGAIN (non-blocking).

    The fixture's 'send_udp_packet' stub swallows 'on_complete'
    without firing it, so outstanding bytes accumulate until a test
    fires the captured hook — exactly what is needed to exercise the
    over-buffer paths deterministically.
    """

    def _connected_socket(self) -> UdpSocket:
        """
        Construct a connected IPv4 UDP socket ready for send().
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 5353))
        return s  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__so_sndbuf__nonblocking_over_buffer_raises_eagain(self) -> None:
        """
        Ensure a non-blocking send that would push the outstanding
        bytes past SO_SNDBUF raises 'BlockingIOError(EAGAIN)' while
        the buffer is not drained.

        Reference: Linux net/core/sock.c sock_alloc_send_pskb
        (SO_SNDBUF bound → EAGAIN when non-blocking).
        """

        from pytcp.runtime.socket import SO_SNDBUF, SOL_SOCKET

        s = self._connected_socket()
        s.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)
        s.setblocking(False)

        # First 80-byte datagram: nothing outstanding, always allowed.
        self.assertEqual(s.send(b"x" * 80), 80, msg="First datagram must be accepted.")
        # Second 80-byte datagram: 80 + 80 > 100 and buffer not drained.
        with self.assertRaises(BlockingIOError) as ctx:
            s.send(b"x" * 80)
        self.assertEqual(
            ctx.exception.errno,
            errno.EAGAIN,
            msg="An over-SO_SNDBUF non-blocking send must raise EAGAIN.",
        )

    def test__so_sndbuf__single_datagram_larger_than_buffer_is_allowed(self) -> None:
        """
        Ensure a single datagram larger than the whole SO_SNDBUF is
        still sent when nothing is outstanding — Linux never wedges a
        lone oversize datagram.

        Reference: Linux net/core/sock.c sock_alloc_send_pskb
        (a send proceeds when the queue is empty).
        """

        from pytcp.runtime.socket import SO_SNDBUF, SOL_SOCKET

        s = self._connected_socket()
        s.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)
        s.setblocking(False)

        self.assertEqual(
            s.send(b"x" * 500),
            500,
            msg="A single datagram larger than SO_SNDBUF must still be accepted.",
        )

    def test__so_sndbuf__completion_hook_releases_and_allows_next_send(self) -> None:
        """
        Ensure firing the 'on_complete' hook passed to
        'send_udp_packet' releases the outstanding bytes so a
        subsequent send that previously would have blocked now
        proceeds — the end-to-end TX-completion release wiring.

        Reference: Linux net/core/sock.c sk_wmem_alloc
        (freed on TX completion, waking blocked senders).
        """

        from pytcp.runtime.socket import SO_SNDBUF, SOL_SOCKET

        captured: list[object] = []

        def _capturing_send(*, on_complete: object = None, **_: object) -> TxStatus:
            captured.append(on_complete)
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        self._handler.send_udp_packet = _capturing_send

        s = self._connected_socket()
        s.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)
        s.setblocking(False)

        s.send(b"x" * 80)
        # Fire the TX-completion hook: outstanding drops back to 0.
        on_complete = captured[-1]
        assert callable(on_complete)
        on_complete()

        # The next 80-byte send now fits again.
        self.assertEqual(
            s.send(b"x" * 80),
            80,
            msg="After the completion hook releases the buffer, the next send must proceed.",
        )

    def test__so_sndbuf__blocking_send_times_out_after_so_sndtimeo(self) -> None:
        """
        Ensure a blocking send that would exceed SO_SNDBUF waits up to
        SO_SNDTIMEO and then raises 'BlockingIOError(EAGAIN)' when no
        space frees — the send-side timeout, mirroring the recv
        SO_RCVTIMEO idiom.

        Reference: Linux net/core/sock.c sock_alloc_send_pskb
        (SO_SNDTIMEO bounds a blocking send → EAGAIN on expiry).
        """

        from pytcp.runtime.socket import SO_SNDBUF, SOL_SOCKET

        s = self._connected_socket()
        s.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)
        # Sub-second SO_SNDTIMEO for a fast test. setsockopt gates
        # SOL_SOCKET on int, so a float timeout is set on the field
        # directly here (the settimeout() surface carries floats for
        # real callers).
        s._so_sndtimeo = 0.05

        s.send(b"x" * 80)
        with self.assertRaises(BlockingIOError) as ctx:
            s.send(b"x" * 80)
        self.assertEqual(
            ctx.exception.errno,
            errno.EAGAIN,
            msg="A blocking over-SO_SNDBUF send must raise EAGAIN after SO_SNDTIMEO.",
        )

    def test__so_sndbuf__unset_default_never_blocks_normal_send(self) -> None:
        """
        Ensure a socket that never sets SO_SNDBUF sends normally — the
        large 'net.core.wmem_default' stand-in means a normally-paced
        sender never meets the bound.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = self._connected_socket()
        s.setblocking(False)

        for _ in range(50):
            self.assertEqual(s.send(b"x" * 1000), 1000, msg="A default-SO_SNDBUF send must not block.")


class TestUdpSocketTimeoutFloat(_UdpSocketTestCase):
    """
    SO_RCVTIMEO / SO_SNDTIMEO accept and report sub-second float
    seconds via setsockopt / getsockopt, matching PyTCP's documented
    'float seconds' surface. The setsockopt SOL_SOCKET int-guard
    previously rejected a float value and getsockopt truncated the
    stored timeout to whole seconds.
    """

    def test__so_rcvtimeo__accepts_and_reports_subsecond_float(self) -> None:
        """
        Ensure setsockopt(SO_RCVTIMEO, 0.5) stores the sub-second
        timeout and getsockopt reports it back verbatim.

        Reference: Linux SO_RCVTIMEO (struct timeval; PyTCP exposes
        float seconds).
        """

        from pytcp.runtime.socket import SO_RCVTIMEO, SOL_SOCKET

        s = UdpSocket(family=AddressFamily.INET4)

        s.setsockopt(SOL_SOCKET, SO_RCVTIMEO, 0.5)
        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_RCVTIMEO),
            0.5,
            msg="SO_RCVTIMEO must round-trip a sub-second float.",
        )

    def test__so_sndtimeo__accepts_and_reports_subsecond_float(self) -> None:
        """
        Ensure setsockopt(SO_SNDTIMEO, 0.25) stores the sub-second
        timeout and getsockopt reports it back verbatim.

        Reference: Linux SO_SNDTIMEO (struct timeval; PyTCP exposes
        float seconds).
        """

        from pytcp.runtime.socket import SO_SNDTIMEO, SOL_SOCKET

        s = UdpSocket(family=AddressFamily.INET4)

        s.setsockopt(SOL_SOCKET, SO_SNDTIMEO, 0.25)
        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_SNDTIMEO),
            0.25,
            msg="SO_SNDTIMEO must round-trip a sub-second float.",
        )

    def test__so_rcvtimeo__integer_seconds_still_accepted(self) -> None:
        """
        Ensure an integer SO_RCVTIMEO still works — regression pin
        for the float widening.

        Reference: Linux SO_RCVTIMEO (integer-second value accepted).
        """

        from pytcp.runtime.socket import SO_RCVTIMEO, SOL_SOCKET

        s = UdpSocket(family=AddressFamily.INET4)

        s.setsockopt(SOL_SOCKET, SO_RCVTIMEO, 3)
        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_RCVTIMEO),
            3,
            msg="SO_RCVTIMEO must still accept an integer-second value.",
        )
