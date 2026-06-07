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
This module contains tests for the 'RawSocket' BSD-like raw socket
implementation.

pytcp/tests/unit/runtime/socket/test__runtime__socket__raw__socket.py

ver 3.0.8
"""

import errno
import fcntl
import select
import struct
from types import SimpleNamespace
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto import Icmp6MessageEchoRequest
from net_proto.lib.enums import IpProto
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.socket import (
    IP_RECVTTL,
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_HOPLIMIT,
    IPV6_RECVHOPLIMIT,
    AddressFamily,
    SocketType,
    gaierror,
)
from pytcp.runtime.socket.raw__metadata import RawMetadata
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.runtime.socket.socket_table import SocketTable


def _make_packet_handler(
    *,
    ip4_unicast: list[Ip4Address] | None = None,
    ip6_unicast: list[Ip6Address] | None = None,
) -> SimpleNamespace:
    """
    Build a minimal 'packet_handler' stub that exposes the attributes
    and methods 'RawSocket' touches: the two unicast-address iterables
    plus 'send_ip4_packet' / 'send_ip6_packet' callables returning a
    'TxStatus'.
    """

    return SimpleNamespace(
        ip4_unicast=ip4_unicast or [Ip4Address("10.0.0.1")],
        ip6_unicast=ip6_unicast or [Ip6Address("2001:db8::1")],
        send_ip4_packet=lambda **_: TxStatus.PASSED__ETHERNET__TO_TX_RING,
        send_ip6_packet=lambda **_: TxStatus.PASSED__ETHERNET__TO_TX_RING,
    )


class _RawSocketTestCase(TestCase):
    """
    Shared fixture for 'RawSocket' tests that pins the module-level
    'log' and 'stack' dependencies so the real stack singletons are
    never touched from the unit-test process.
    """

    def setUp(self) -> None:
        """
        Patch logging, the socket registry, and the packet handler for
        the duration of the test.

        Patches register their stops via 'addCleanup' so test-level
        'self.addCleanup(s.close)' callbacks (LIFO-popped first) run
        while the 'log' patch is still active. Otherwise socket close
        logs leak through to stdout.
        """

        self._log_patch = patch("pytcp.runtime.socket.raw__socket.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._sockets = SocketTable()
        self._sockets_patch = patch(
            "pytcp.runtime.socket.raw__socket.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()
        self.addCleanup(self._sockets_patch.stop)

        self._handler = _make_packet_handler()

        # Phase-6 seams: socket-originated TX resolves its egress via
        # 'stack.egress_packet_handler()' and source validation spans all
        # interfaces via 'stack.local_ip{4,6}_unicast()'. Point both at this
        # fixture's local stub handler; reading 'self._handler' lazily lets
        # a per-test reassignment transparently drive the send path.
        self._egress_patch = patch(
            "pytcp.runtime.socket.raw__socket.stack.egress_packet_handler",
            side_effect=lambda *_a: self._handler,
        )
        self._egress_patch.start()
        self.addCleanup(self._egress_patch.stop)

        # Routing is not under test in these stubbed-TX fixtures; pin the
        # no-route EHOSTUNREACH check True so a FIB leaked into globals by
        # an earlier suite test cannot spuriously fail these sends.
        self._has_route_patch = patch(
            "pytcp.runtime.socket.raw__socket.stack.has_route_to",
            return_value=True,
        )
        self._has_route_patch.start()
        self.addCleanup(self._has_route_patch.stop)
        for _helper, _attr in (("local_ip4_unicast", "ip4_unicast"), ("local_ip6_unicast", "ip6_unicast")):
            _p = patch(
                f"pytcp.runtime.socket.raw__socket.stack.{_helper}",
                side_effect=lambda attr=_attr: tuple(getattr(self._handler, attr)),
            )
            _p.start()
            self.addCleanup(_p.stop)


class TestRawSocketInit(_RawSocketTestCase):
    """
    The 'RawSocket.__init__' tests.
    """

    def test__raw_socket__init_ip4_no_protocol_raises_eprotonosupport(self) -> None:
        """
        Ensure constructing an IPv4 'RawSocket' with no explicit
        protocol raises 'OSError(EPROTONOSUPPORT)'. Raw sockets must
        carry an explicit IANA next-header value; there is no
        meaningful default, so PyTCP mirrors Linux's 'sys_socket'
        behavior of returning 'EPROTONOSUPPORT' for this case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            RawSocket(AddressFamily.INET4)
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="RawSocket(INET4) with no protocol must raise OSError(EPROTONOSUPPORT).",
        )

    def test__raw_socket__init_ip6_no_protocol_raises_eprotonosupport(self) -> None:
        """
        Ensure constructing an IPv6 'RawSocket' with no explicit
        protocol raises 'OSError(EPROTONOSUPPORT)' — symmetric with
        the IPv4 case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            RawSocket(AddressFamily.INET6)
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="RawSocket(INET6) with no protocol must raise OSError(EPROTONOSUPPORT).",
        )

    def test__raw_socket__init_explicit_protocol(self) -> None:
        """
        Ensure an explicit 'protocol=' is stored on '_ip_proto' and
        the 'local_port' shadow mirrors 'int(protocol)' so the
        socket-registry lookup key is unique per protocol.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)

        self.assertIs(s.address_family, AddressFamily.INET4, msg="address_family must be INET4.")
        self.assertIs(s.socket_type, SocketType.RAW, msg="socket_type must be RAW.")
        self.assertIs(
            s.ip_proto,
            IpProto.ICMP4,
            msg="Explicit IpProto.ICMP4 must be stored on _ip_proto.",
        )
        self.assertEqual(
            s.local_ip_address,
            Ip4Address(),
            msg="local_ip_address must start unspecified for IPv4.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address(),
            msg="remote_ip_address must start unspecified for IPv4.",
        )
        self.assertEqual(
            s.local_port,
            int(IpProto.ICMP4),
            msg="local_port must equal int(ip_proto) after construction.",
        )
        self.assertEqual(s.remote_port, 0, msg="remote_port must start at 0 for raw sockets.")

    def test__raw_socket__init_explicit_ipv6_protocol(self) -> None:
        """
        Ensure an explicit IPv6 protocol (e.g. 'IpProto.ICMP6') is
        stored on '_ip_proto' and selects the IPv6 unspecified-
        address placeholders for the local/remote bind state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)

        self.assertIs(
            s.ip_proto,
            IpProto.ICMP6,
            msg="Explicit IpProto.ICMP6 must be stored on _ip_proto.",
        )
        self.assertEqual(
            s.local_ip_address,
            Ip6Address(),
            msg="local_ip_address must start unspecified for IPv6.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip6Address(),
            msg="remote_ip_address must start unspecified for IPv6.",
        )

    def test__raw_socket__init_rejects_non_raw_type(self) -> None:
        """
        Ensure constructing with any 'SocketType' other than 'RAW'
        fires the 'assert type is SocketType.RAW' guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            RawSocket(
                family=AddressFamily.INET4,
                type=SocketType.STREAM,
                protocol=IpProto.ICMP4,
            )


class TestRawSocketBind(_RawSocketTestCase):
    """
    The 'RawSocket.bind' tests.
    """

    def test__raw_socket__bind_accepts_stack_owned_address(self) -> None:
        """
        Ensure binding to a specific local IPv4 address that the stack
        owns succeeds, updates 'local_ip_address', and registers the
        socket in 'stack.sockets'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.bind(("10.0.0.1", 0))

        self.assertEqual(
            s.local_ip_address,
            Ip4Address("10.0.0.1"),
            msg="bind() must set local_ip_address to the provided stack-owned address.",
        )
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="bind() must register the socket on stack.sockets under its socket_id.",
        )

    def test__raw_socket__bind_accepts_unspecified_address(self) -> None:
        """
        Ensure binding to '0.0.0.0' (the unspecified IPv4 address) is
        always accepted regardless of the stack's unicast list — it
        represents a wildcard bind.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.bind(("0.0.0.0", 0))

        self.assertEqual(
            s.local_ip_address,
            Ip4Address(),
            msg="bind() must accept the IPv4 unspecified address as a wildcard.",
        )

    def test__raw_socket__bind_rejects_foreign_address(self) -> None:
        """
        Ensure binding to an IPv4 address not owned by the stack raises
        'OSError' with the canonical Errno 99 message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise with Errno 99 when the local IP is not stack-owned.",
        )

    def test__raw_socket__bind_rejects_malformed_ip4(self) -> None:
        """
        Ensure a malformed IPv4 literal raises 'gaierror' — the
        stack-level alias for 'socket.gaierror'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(gaierror):
            s.bind(("not-an-ip", 0))

    def test__raw_socket__bind_ip6_rejects_foreign_address(self) -> None:
        """
        Ensure the IPv6 branch also checks the stack's unicast set and
        raises Errno 99 when the address is not owned.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with self.assertRaises(OSError) as context:
            s.bind(("2001:db8:dead::1", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise with Errno 99 for foreign IPv6 addresses.",
        )

    def test__raw_socket__bind_ip6_rejects_malformed_address(self) -> None:
        """
        Ensure malformed IPv6 literals raise 'gaierror'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with self.assertRaises(gaierror):
            s.bind(("not-a-v6", 0))


class TestRawSocketConnect(_RawSocketTestCase):
    """
    The 'RawSocket.connect' tests.
    """

    def test__raw_socket__connect_sets_remote_and_picks_local(self) -> None:
        """
        Ensure connect() validates the remote IP, delegates to
        'pick_local_ip_address' when the local IP is unspecified, and
        stores both sides plus the remote port.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ) as pick:
            s.connect(("10.0.0.5", 7))

        pick.assert_called_once()
        self.assertEqual(
            s.local_ip_address,
            Ip4Address("10.0.0.1"),
            msg="connect() must set the local IP from pick_local_ip_address when starting unspecified.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address("10.0.0.5"),
            msg="connect() must set the remote IP from the address argument.",
        )
        self.assertEqual(s.remote_port, 7, msg="connect() must store the remote port verbatim.")

    def test__raw_socket__connect_rejects_out_of_range_port(self) -> None:
        """
        Ensure connect() raises 'OverflowError' for a port value
        outside the 0-65535 inclusive range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(OverflowError):
            s.connect(("10.0.0.5", 70000))

    def test__raw_socket__connect_rejects_malformed_remote_address(self) -> None:
        """
        Ensure connect() raises 'gaierror' when the remote address
        literal is malformed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(gaierror):
            s.connect(("not-an-ip", 7))

    def test__raw_socket__connect_rejects_unroutable_remote(self) -> None:
        """
        Ensure connect() raises 'gaierror' when the helper cannot pick
        a local IP address (both the stack-provided and fallback
        picks would be unspecified).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address(),
        ):
            with self.assertRaises(gaierror):
                s.connect(("10.0.0.5", 7))


class TestRawSocketSend(_RawSocketTestCase):
    """
    The 'RawSocket.send' / 'RawSocket.sendto' tests.
    """

    def test__raw_socket__send_requires_connect(self) -> None:
        """
        Ensure send() raises 'OSError' with the Errno 89 message when
        called before connect(), because the remote IP is still the
        unspecified placeholder.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(OSError) as context:
            s.send(b"data")
        self.assertIn(
            "[Errno 89]",
            str(context.exception),
            msg="send() must raise with Errno 89 when no destination is set.",
        )

    def test__raw_socket__send_ip4_returns_bytes_sent(self) -> None:
        """
        Ensure send() dispatches to 'send_ip4_packet' for an IPv4 raw
        socket and returns 'len(data)' on 'PASSED__ETHERNET__TO_TX_RING'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.connect(("10.0.0.5", 7))
        self.assertEqual(
            s.send(b"hello"),
            5,
            msg="send() must return the number of bytes enqueued for transmission.",
        )

    def test__raw_socket__send_ip6_returns_bytes_sent(self) -> None:
        """
        Ensure send() dispatches to 'send_ip6_packet' for an IPv6 raw
        socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip6Address("2001:db8::1"),
        ):
            s.connect(("2001:db8::2", 7))
        self.assertEqual(
            s.send(b"data"),
            4,
            msg="send() on an IPv6 raw socket must route through send_ip6_packet.",
        )

    def test__raw_socket__send_returns_len_data_even_on_drop(self) -> None:
        """
        Ensure send() returns 'len(data)' even when the TX path would
        ultimately drop the packet. Phase 4b made the raw send path
        fire-and-forget: the packet is accepted into the stack the
        moment it is queued on the TX worker; delivery failures
        surface asynchronously, never via send()'s return value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Point the egress seam at a drop-everything stub (the fixture's
        # 'egress_packet_handler' side_effect reads 'self._handler' lazily).
        self._handler = _make_packet_handler()
        self._handler.send_ip4_packet = lambda **_: None
        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.connect(("10.0.0.5", 7))
        self.assertEqual(
            s.send(b"data"),
            4,
            msg="send() must return len(data) — fire-and-forget accepts the packet regardless of drop.",
        )

    def test__raw_socket__sendto_does_not_require_connect(self) -> None:
        """
        Ensure sendto() can transmit without a prior connect() — it
        derives the remote from its 'address' argument and the local
        from 'pick_local_ip_address'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            self.assertEqual(
                s.sendto(b"hello", ("10.0.0.5", 7)),
                5,
                msg="sendto() must return the number of bytes enqueued without requiring connect().",
            )

    def test__raw_socket__sendto_ip6_returns_bytes_sent(self) -> None:
        """
        Ensure sendto() dispatches to 'send_ip6_packet' for an IPv6
        raw socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip6Address("2001:db8::1"),
        ):
            self.assertEqual(
                s.sendto(b"data", ("2001:db8::2", 7)),
                4,
                msg="sendto() on an IPv6 raw socket must route through send_ip6_packet.",
            )


class TestRawSocketSendmsg(_RawSocketTestCase):
    """
    The 'RawSocket.sendmsg' / 'RawSocket.recvmsg' tests.
    """

    def _make_md(self) -> RawMetadata:
        """
        Build a canonical IPv4 'RawMetadata' envelope to feed the
        socket's receive path.
        """

        return RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=b"payload",
        )

    def test__raw_socket__sendmsg_concatenates_buffers_with_address(self) -> None:
        """
        Ensure sendmsg() with an explicit 'address' concatenates the
        scatter-gather buffers and sends like sendto() on an
        unconnected raw socket, returning the total byte count.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            self.assertEqual(
                s.sendmsg([b"AB", b"CD"], address=("10.0.0.5", 7)),
                4,
                msg="sendmsg(address=...) must concatenate buffers and send like sendto().",
            )

    def test__raw_socket__sendmsg_rejects_malformed_ancdata(self) -> None:
        """
        Ensure sendmsg() rejects an ancillary-data entry that is not a
        3-tuple with a TypeError, matching the stdlib structural
        contract.

        Reference: socket(7) sendmsg (ancillary-data structure).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        bad_ancdata: list[Any] = [(1, 2)]
        with self.assertRaises(TypeError):
            s.sendmsg([b"x"], bad_ancdata, address=("10.0.0.5", 7))

    def test__raw_socket__recvmsg_returns_quadruple_with_empty_ancdata(self) -> None:
        """
        Ensure recvmsg() returns the stdlib
        '(data, ancdata, msg_flags, address)' quadruple with an empty
        ancillary-data list when no TTL-delivery option is enabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        data, ancdata, msg_flags, address = s.recvmsg()
        self.assertEqual(
            data,
            b"payload",
            msg="recvmsg() must return the raw__data as the first tuple element.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="recvmsg() with no TTL option set must return an empty ancillary-data list.",
        )
        self.assertEqual(
            msg_flags,
            0,
            msg="recvmsg() must return msg_flags=0 for a raw socket.",
        )
        self.assertEqual(
            address,
            ("10.0.0.2", 0),
            msg="recvmsg() must return (remote_ip_str, 0) as the address.",
        )

    def test__raw_socket__recvmsg_delivers_hop_limit_cmsg_ip6(self) -> None:
        """
        Ensure an IPv6 raw socket with 'IPV6_RECVHOPLIMIT' set surfaces
        the received Hop Limit as an 'IPV6_HOPLIMIT' cmsg — the only way
        to read it on a v6 raw socket, which carries no IP header.

        Reference: RFC 3542 §6.3 (IPV6_RECVHOPLIMIT / IPV6_HOPLIMIT cmsg).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        s.setsockopt(IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
        s.process_raw_packet(
            RawMetadata(
                ip__ver=IpVersion.IP6,
                ip__local_address=Ip6Address("2603:808c:2800:4301::7"),
                ip__remote_address=Ip6Address("2600::"),
                ip__proto=IpProto.ICMP6,
                ip__ttl=48,
                raw__data=b"icmp6",
            )
        )

        _data, ancdata, _flags, _address = s.recvmsg()
        self.assertEqual(
            ancdata,
            [(int(IPPROTO_IPV6), int(IPV6_HOPLIMIT), (48).to_bytes(4, "little"))],
            msg="recvmsg() must surface the received Hop Limit as an IPV6_HOPLIMIT cmsg.",
        )

    def test__raw_socket__recvmsg_delivers_ttl_cmsg_ip4(self) -> None:
        """
        Ensure an IPv4 raw socket with 'IP_RECVTTL' set surfaces the
        received TTL as an 'IP_TTL' cmsg.

        Reference: RFC 3542 §6.3 (IP_RECVTTL / IP_TTL cmsg, IPv4 analogue).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.setsockopt(IPPROTO_IP, IP_RECVTTL, 1)
        s.process_raw_packet(
            RawMetadata(
                ip__ver=IpVersion.IP4,
                ip__local_address=Ip4Address("10.0.0.1"),
                ip__remote_address=Ip4Address("10.0.0.2"),
                ip__proto=IpProto.ICMP4,
                ip__ttl=57,
                raw__data=b"icmp4",
            )
        )

        _data, ancdata, _flags, _address = s.recvmsg()
        self.assertEqual(
            ancdata,
            [(int(IPPROTO_IP), int(IP_TTL), (57).to_bytes(4, "little"))],
            msg="recvmsg() must surface the received TTL as an IP_TTL cmsg.",
        )


class TestRawSocketDscp(_RawSocketTestCase):
    """
    The per-socket DSCP marking (IP_TOS / IPV6_TCLASS high 6 bits)
    threading from 'RawSocket.send' / 'sendto' into the IP TX path.
    """

    def test__raw_socket__effective_ip_dscp__extracts_high_six_bits_ipv4(self) -> None:
        """
        Ensure '_effective_ip_dscp()' returns the high 6 bits of the
        IPv4 socket's IP_TOS byte and '_effective_ip_ecn()' the low 2.

        Reference: RFC 2474 §3 (DS field — DSCP high 6 / ECN low 2).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s._ip_tos = (46 << 2) | 2

        self.assertEqual(s._effective_ip_dscp(), 46, msg="DSCP must be the high 6 bits of IP_TOS.")
        self.assertEqual(s._effective_ip_ecn(), 2, msg="ECN must be the low 2 bits of IP_TOS.")

    def test__raw_socket__effective_ip_dscp__extracts_high_six_bits_ipv6(self) -> None:
        """
        Ensure '_effective_ip_dscp()' returns the high 6 bits of the
        IPv6 socket's IPV6_TCLASS byte.

        Reference: RFC 2474 §3 (DS field — DSCP high 6 / ECN low 2).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        s._ipv6_tclass = (46 << 2) | 2

        self.assertEqual(s._effective_ip_dscp(), 46, msg="DSCP must be the high 6 bits of IPV6_TCLASS.")
        self.assertEqual(s._effective_ip_ecn(), 2, msg="ECN must be the low 2 bits of IPV6_TCLASS.")

    def test__raw_socket__send_threads_ipv4_dscp_to_ip_layer(self) -> None:
        """
        Ensure send() passes the socket's effective DSCP through to
        'send_ip4_packet' as 'ip4__dscp'.

        Reference: RFC 2474 §3 (DS field — DSCP marking on transmit).
        """

        captured: dict[str, Any] = {}
        self._handler.send_ip4_packet = lambda **kwargs: captured.update(kwargs)

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s._ip_tos = 46 << 2
        with patch(
            "pytcp.runtime.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.connect(("10.0.0.5", 7))
        s.send(b"data")

        self.assertEqual(
            captured.get("ip4__dscp"),
            46,
            msg="send() must thread the socket's effective DSCP into send_ip4_packet(ip4__dscp=).",
        )


class TestRawSocketReceive(_RawSocketTestCase):
    """
    The 'RawSocket.recv' / 'RawSocket.recvfrom' / 'process_raw_packet'
    tests.
    """

    def _make_md(self) -> RawMetadata:
        """
        Build a canonical IPv4 'RawMetadata' envelope to feed the
        socket's receive path.
        """

        from net_addr import IpVersion

        return RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=b"payload",
        )

    def test__raw_socket__process_raw_packet_enqueues(self) -> None:
        """
        Ensure 'process_raw_packet' appends the metadata to the RX
        queue and releases the 'packet_rx_md_ready' semaphore exactly
        once per packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        self.assertEqual(
            len(s._packet_rx_md),
            1,
            msg="process_raw_packet must enqueue exactly one metadata entry.",
        )

    def test__raw_socket__recv_returns_payload(self) -> None:
        """
        Ensure recv() dequeues the next metadata entry, returns its
        'raw__data' as 'bytes', and honors the queued-packet ordering.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        self.assertEqual(
            s.recv(),
            b"payload",
            msg="recv() must return the queued metadata's raw__data as bytes.",
        )

    def test__raw_socket__recv_timeout_raises(self) -> None:
        """
        Ensure recv() with a finite timeout raises 'TimeoutError' when
        no packet arrives within the window.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(TimeoutError):
            s.recv(timeout=0.01)

    def test__raw_socket__recvfrom_returns_payload_and_addr(self) -> None:
        """
        Ensure recvfrom() returns a (bytes, (str_ip, 0)) tuple. The
        port is always 0 for raw sockets since there is no L4 port.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        data, addr = s.recvfrom()
        self.assertEqual(
            data,
            b"payload",
            msg="recvfrom() must return the raw__data as the first tuple element.",
        )
        self.assertEqual(
            addr,
            ("10.0.0.2", 0),
            msg="recvfrom() must return (remote_ip_str, 0) as the second tuple element.",
        )

    def test__raw_socket__recvfrom_timeout_raises(self) -> None:
        """
        Ensure recvfrom() with a finite timeout raises 'TimeoutError'
        when no packet arrives within the window.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(TimeoutError):
            s.recvfrom(timeout=0.01)


class TestRawSocketClose(_RawSocketTestCase):
    """
    The 'RawSocket.close' teardown tests.
    """

    def test__raw_socket__close_removes_socket_from_registry(self) -> None:
        """
        Ensure close() removes the socket from 'stack.sockets' so
        subsequent packets cannot reach it. Closing a socket that was
        never bound is a no-op.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.bind(("10.0.0.1", 0))
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="Precondition: bind() must register the socket.",
        )

        s.close()

        self.assertNotIn(
            s.socket_id,
            self._sockets,
            msg="close() must remove the socket from stack.sockets.",
        )

    def test__raw_socket__close_is_idempotent(self) -> None:
        """
        Ensure close() does not raise when called on an unbound socket
        — it must treat 'socket not in registry' as success.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.close()  # must not raise


class TestRawSocketFileno(_RawSocketTestCase):
    """
    The 'RawSocket.fileno' / read-readiness signal-and-drain tests.
    """

    def _make_md(self, data: bytes = b"payload") -> RawMetadata:
        """
        Build a canonical IPv4 'RawMetadata' envelope.
        """

        from net_addr import IpVersion

        return RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=data,
        )

    def setUp(self) -> None:
        """
        Build a fresh raw socket. 'tearDown' closes it before the
        parent fixture stops the 'log' patch so the close-time log
        line stays suppressed.
        """

        super().setUp()
        self._socket = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)

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

    def test__raw_socket__fileno_returns_non_negative_int(self) -> None:
        """
        Ensure 'fileno()' on a raw socket returns a non-negative
        integer file descriptor for selector consumption.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()

        self.assertIsInstance(
            fd,
            int,
            msg="RawSocket.fileno() must return an int.",
        )
        self.assertGreaterEqual(
            fd,
            0,
            msg="RawSocket.fileno() must return a non-negative fd.",
        )

    def test__raw_socket__fileno_initially_not_select_ready(self) -> None:
        """
        Ensure a freshly-constructed raw socket is not select-readable
        before any packet has been delivered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="A fresh RawSocket must not be select-readable.",
        )

    def test__raw_socket__fileno_select_ready_after_packet_arrives(self) -> None:
        """
        Ensure 'process_raw_packet' transitions the fd into the
        select-readable state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md())

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="process_raw_packet must mark the fd as select-readable.",
        )

    def test__raw_socket__fileno_drained_after_recv_consumes_last_packet(self) -> None:
        """
        Ensure 'recv()' returns the fd to the not-readable state
        once the last queued packet has been consumed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md())
        self._socket.recv()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="recv() draining the last packet must clear the readable bit.",
        )

    def test__raw_socket__close_closes_underlying_fd(self) -> None:
        """
        Ensure 'close()' tears down the eventfd backing 'fileno()'.

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


class TestRawSocketNonBlocking(_RawSocketTestCase):
    """
    The 'RawSocket.setblocking' non-blocking-recv tests.
    """

    def setUp(self) -> None:
        """
        Build a non-blocking raw socket. tearDown closes it before
        the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self._socket.setblocking(False)

    def tearDown(self) -> None:
        """
        Close the socket before the parent tears down patches.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__raw_socket__recv_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recv()' on a non-blocking raw socket with an empty
        queue raises 'BlockingIOError(EAGAIN)' to match POSIX
        'O_NONBLOCK' semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recv()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recv() with no data must raise BlockingIOError(EAGAIN).",
        )

    def test__raw_socket__recvfrom_raises_blocking_io_error_when_no_data(self) -> None:
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


class TestRawSocketRecvBufsize(_RawSocketTestCase):
    """
    The 'RawSocket.recv' / 'recvfrom' bufsize-truncation tests.
    """

    def _make_md(self, data: bytes) -> RawMetadata:
        """
        Build a canonical IPv4 RawMetadata envelope.
        """

        from net_addr import IpVersion

        return RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=data,
        )

    def setUp(self) -> None:
        """
        Build a raw socket; tearDown closes it before the parent
        fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)

    def tearDown(self) -> None:
        """
        Close the socket before the parent tears down patches.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__raw_socket__recv_truncates_oversized_packet_to_bufsize(self) -> None:
        """
        Ensure 'recv(bufsize)' on a raw socket returns at most
        'bufsize' bytes when the queued packet exceeds it; the
        remainder is silently discarded per POSIX 'recv(2)' on
        SOCK_RAW.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md(b"abcdefghij"))

        self.assertEqual(
            self._socket.recv(bufsize=4),
            b"abcd",
            msg="recv(bufsize=4) on a 10-byte raw packet must return the first 4 bytes only.",
        )

    def test__raw_socket__recv_with_bufsize_returns_full_when_smaller(self) -> None:
        """
        Ensure 'recv(bufsize)' returns the full packet when the
        packet is smaller than 'bufsize' — the bufsize is a ceiling.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md(b"hi"))

        self.assertEqual(
            self._socket.recv(bufsize=1024),
            b"hi",
            msg="recv(bufsize=1024) on a 2-byte raw packet must return the full payload.",
        )

    def test__raw_socket__recv_with_bufsize_none_returns_full_payload(self) -> None:
        """
        Ensure 'recv()' with no 'bufsize' argument returns the
        complete raw packet — preserves the existing default
        behavior.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = b"x" * 200
        self._socket.process_raw_packet(self._make_md(payload))

        self.assertEqual(
            self._socket.recv(),
            payload,
            msg="recv() without bufsize must return the full raw packet.",
        )

    def test__raw_socket__recvfrom_truncates_oversized_packet_to_bufsize(self) -> None:
        """
        Ensure 'recvfrom(bufsize)' parallels 'recv(bufsize)' by
        truncating while still returning the sender's (ip, 0)
        tuple.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md(b"abcdefghij"))

        data, addr = self._socket.recvfrom(bufsize=3)

        self.assertEqual(
            data,
            b"abc",
            msg="recvfrom(bufsize=3) must truncate the payload to 3 bytes.",
        )
        self.assertEqual(
            addr,
            ("10.0.0.2", 0),
            msg="recvfrom(bufsize=3) must still return the (ip, 0) tuple.",
        )


class TestRawSocketErrnoMapping(_RawSocketTestCase):
    """
    The 'RawSocket' OSError errno-mapping tests.
    """

    def test__raw_socket__bind_foreign_ip_carries_eaddrnotavail_errno(self) -> None:
        """
        Ensure 'bind()' to a non-stack-owned IP raises 'OSError'
        with '.errno == errno.EADDRNOTAVAIL'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))

        self.assertEqual(
            context.exception.errno,
            errno.EADDRNOTAVAIL,
            msg="foreign-IP bind OSError must carry errno=EADDRNOTAVAIL.",
        )

    def test__raw_socket__send_no_destination_carries_edestaddrreq_errno(self) -> None:
        """
        Ensure 'send()' on a socket with no remote IP raises
        'OSError' with '.errno == errno.EDESTADDRREQ'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self.addCleanup(s.close)

        with self.assertRaises(OSError) as context:
            s.send(b"data")

        self.assertEqual(
            context.exception.errno,
            errno.EDESTADDRREQ,
            msg="send-without-destination OSError must carry errno=EDESTADDRREQ.",
        )


class TestRawSocketIcmp6Checksum(_RawSocketTestCase):
    """
    The IPv6 raw-socket mandatory ICMPv6-checksum tests.
    """

    def test__raw_socket__icmp6_checksum_auto_computed(self) -> None:
        """
        Ensure an IPPROTO_ICMPV6 raw socket fills the mandatory ICMPv6
        checksum over the IPv6 pseudo-header (the application leaves it
        zero, since it cannot see the stack-selected source address).

        Reference: RFC 4443 §2.3 (ICMPv6 checksum over the pseudo-header).
        """

        sock = RawSocket(AddressFamily.INET6, SocketType.RAW, IpProto.ICMP6)
        self.addCleanup(sock.close)

        local = Ip6Address("2603:808c:2800:4301::7")
        remote = Ip6Address("2600::")
        request = bytearray(bytes(Icmp6MessageEchoRequest(id=0x1234, seq=1, data=b"ping-data")))
        request[2:4] = b"\x00\x00"  # zero the checksum field, as an app would

        result = sock._icmp6_checksummed(bytes(request), local=local, remote=remote)

        self.assertNotEqual(result[2:4], b"\x00\x00", msg="The socket must fill the zeroed ICMPv6 checksum field.")
        pshdr_sum = sum(
            struct.unpack(
                "! 5Q",
                struct.pack("! 16s 16s L BBBB", bytes(local), bytes(remote), len(result), 0, 0, 0, int(IpProto.ICMP6)),
            )
        )
        self.assertEqual(
            inet_cksum(result, init=pshdr_sum),
            0,
            msg="The filled ICMPv6 checksum must make the pseudo-header-covered sum zero (a valid checksum).",
        )

    def test__raw_socket__non_icmp6_payload_unchanged(self) -> None:
        """
        Ensure a non-ICMPv6 raw socket leaves the application payload
        untouched (only IPPROTO_ICMPV6 gets the forced checksum).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = RawSocket(AddressFamily.INET6, SocketType.RAW, IpProto.TCP)
        self.addCleanup(sock.close)

        payload = b"\x00\x01\x02\x03\x04\x05"
        result = sock._icmp6_checksummed(
            payload,
            local=Ip6Address("2603:808c:2800:4301::7"),
            remote=Ip6Address("2600::"),
        )

        self.assertEqual(result, payload, msg="A non-ICMPv6 raw socket must not rewrite the payload.")
