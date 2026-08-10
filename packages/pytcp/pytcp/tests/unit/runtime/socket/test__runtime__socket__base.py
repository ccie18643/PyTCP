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
This module contains tests for the BSD-like 'socket' base class and its
companion enums ('AddressFamily', 'SocketType') plus the 'gaierror' shim.

pytcp/tests/unit/runtime/socket/test__runtime__socket__base.py

ver 3.0.10
"""

import errno
import fcntl
import select
from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.runtime.socket import (
    AF_INET,
    AF_INET4,
    AF_INET6,
    AF_PACKET,
    ETH_P_ALL,
    IPPROTO_ICMP,
    IPPROTO_ICMP4,
    IPPROTO_ICMP6,
    IPPROTO_ICMPV6,
    IPPROTO_IP,
    IPPROTO_IP6,
    IPPROTO_IPIP,
    IPPROTO_IPV6,
    IPPROTO_RAW,
    IPPROTO_TCP,
    IPPROTO_UDP,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_STREAM,
    AddressFamily,
    SocketType,
    gaierror,
    socket,
)
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.runtime.socket.socket_id import SocketId
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.runtime.socket.udp__socket import UdpSocket


class TestGaierror(TestCase):
    """
    The 'gaierror' exception shim tests.
    """

    def test__socket__gaierror_is_oserror_subclass(self) -> None:
        """
        Ensure 'gaierror' is a subclass of 'OSError' so callers written
        against the stdlib BSD socket API catch it via the broader
        exception class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(gaierror, OSError),
            msg="gaierror must inherit from OSError to match stdlib socket semantics.",
        )

    def test__socket__gaierror_preserves_message(self) -> None:
        """
        Ensure raising 'gaierror' preserves the supplied message through
        'str(exc)' so error-matching tests can assert on the exact text.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(gaierror) as context:
            raise gaierror("boom")

        self.assertEqual(
            str(context.exception),
            "boom",
            msg="gaierror must preserve the supplied message in str().",
        )


class TestAddressFamily(TestCase):
    """
    The 'AddressFamily' enum tests.
    """

    def test__socket__address_family_members(self) -> None:
        """
        Ensure the 'AddressFamily' enum has exactly the 'INET4' and
        'INET6' members with their canonical integer values. Downstream
        match statements rely on both the member identity and the value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(AddressFamily.INET4),
            1,
            msg="AddressFamily.INET4 must have the canonical integer value 1.",
        )
        self.assertEqual(
            int(AddressFamily.INET6),
            2,
            msg="AddressFamily.INET6 must have the canonical integer value 2.",
        )

    def test__socket__address_family_aliases(self) -> None:
        """
        Ensure the 'AF_INET', 'AF_INET4', and 'AF_INET6' module-level
        aliases point at the corresponding 'AddressFamily' members so
        BSD-API-style constants resolve correctly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            AF_INET,
            AddressFamily.INET4,
            msg="AF_INET alias must resolve to AddressFamily.INET4.",
        )
        self.assertIs(
            AF_INET4,
            AddressFamily.INET4,
            msg="AF_INET4 alias must resolve to AddressFamily.INET4.",
        )
        self.assertIs(
            AF_INET6,
            AddressFamily.INET6,
            msg="AF_INET6 alias must resolve to AddressFamily.INET6.",
        )

    def test__socket__address_family_str_is_name(self) -> None:
        """
        Ensure 'AddressFamily' members stringify as their name, not
        their integer value. The 'NameEnum' base overrides '__str__'
        so log lines carry readable identifiers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(AddressFamily.INET4),
            "INET4",
            msg="AddressFamily.INET4 must stringify as its name.",
        )
        self.assertEqual(
            str(AddressFamily.INET6),
            "INET6",
            msg="AddressFamily.INET6 must stringify as its name.",
        )

    def test__socket__address_family_from_ver_ip4(self) -> None:
        """
        Ensure 'AddressFamily.from_ver()' maps 'IpVersion.IP4' to
        'AddressFamily.INET4'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            AddressFamily.from_ver(IpVersion.IP4),
            AddressFamily.INET4,
            msg="AddressFamily.from_ver(IP4) must return AddressFamily.INET4.",
        )

    def test__socket__address_family_from_ver_ip6(self) -> None:
        """
        Ensure 'AddressFamily.from_ver()' maps 'IpVersion.IP6' to
        'AddressFamily.INET6'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            AddressFamily.from_ver(IpVersion.IP6),
            AddressFamily.INET6,
            msg="AddressFamily.from_ver(IP6) must return AddressFamily.INET6.",
        )

    def test__socket__address_family_packet_member(self) -> None:
        """
        Ensure the 'AddressFamily' enum carries a 'PACKET' member with
        the canonical Linux 'AF_PACKET' integer value 17, and that the
        'AF_PACKET' module-level alias resolves to it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(AddressFamily.PACKET),
            17,
            msg="AddressFamily.PACKET must carry the canonical Linux AF_PACKET value 17.",
        )
        self.assertIs(
            AF_PACKET,
            AddressFamily.PACKET,
            msg="AF_PACKET alias must resolve to AddressFamily.PACKET.",
        )


class TestSocketType(TestCase):
    """
    The 'SocketType' enum tests.
    """

    def test__socket__socket_type_members(self) -> None:
        """
        Ensure the 'SocketType' enum exposes 'STREAM', 'DGRAM', and
        'RAW' with their canonical integer values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(SocketType.STREAM),
            1,
            msg="SocketType.STREAM must have the canonical integer value 1.",
        )
        self.assertEqual(
            int(SocketType.DGRAM),
            2,
            msg="SocketType.DGRAM must have the canonical integer value 2.",
        )
        self.assertEqual(
            int(SocketType.RAW),
            3,
            msg="SocketType.RAW must have the canonical integer value 3.",
        )

    def test__socket__socket_type_aliases(self) -> None:
        """
        Ensure the 'SOCK_STREAM', 'SOCK_DGRAM', 'SOCK_RAW' module-level
        aliases point at the corresponding 'SocketType' members.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            SOCK_STREAM,
            SocketType.STREAM,
            msg="SOCK_STREAM alias must resolve to SocketType.STREAM.",
        )
        self.assertIs(
            SOCK_DGRAM,
            SocketType.DGRAM,
            msg="SOCK_DGRAM alias must resolve to SocketType.DGRAM.",
        )
        self.assertIs(
            SOCK_RAW,
            SocketType.RAW,
            msg="SOCK_RAW alias must resolve to SocketType.RAW.",
        )

    def test__socket__socket_type_str_is_name(self) -> None:
        """
        Ensure 'SocketType' members stringify as their member name so
        log lines use the human-readable identifier.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(SocketType.STREAM),
            "STREAM",
            msg="SocketType.STREAM must stringify as its name.",
        )


class TestIpProtoAliases(TestCase):
    """
    The module-level 'IPPROTO_*' alias tests.
    """

    def test__socket__ipproto_ip_is_bsd_default_protocol_sentinel(self) -> None:
        """
        Ensure 'IPPROTO_IP' is exposed as a plain 'int' equal to 0 — the
        BSD '<netinet/in.h>' "default protocol" sentinel — and is NOT an
        'IpProto' enum member. The BSD sentinel and the IANA next-header
        namespace must stay decoupled so the IpProto enum member with
        value 0 (Hop-by-Hop Options) can coexist without an alias
        collision.

        Reference: RFC 2003 §1 (IPv4-in-IPv4 IANA protocol number 4).
        Reference: RFC 8200 §4.3 (Hop-by-Hop Options, next-header value 0).
        """

        self.assertIsInstance(
            IPPROTO_IP,
            int,
            msg="IPPROTO_IP must be a plain int per BSD <netinet/in.h>.",
        )
        self.assertNotIsInstance(
            IPPROTO_IP,
            IpProto,
            msg=(
                "IPPROTO_IP must not be an IpProto member — it is the BSD "
                "default-protocol sentinel, not an IANA next-header value."
            ),
        )
        self.assertEqual(
            IPPROTO_IP,
            0,
            msg="IPPROTO_IP must equal 0 per BSD <netinet/in.h>.",
        )

    def test__socket__ipproto_ipip_aliases_ip4(self) -> None:
        """
        Ensure 'IPPROTO_IPIP' (Linux's stdlib name for IPv4-in-IPv4)
        aliases 'IpProto.IP4' and that 'int(IPPROTO_IPIP) == 4' matches
        the IANA-assigned protocol number for IPv4 encapsulation.

        Reference: RFC 2003 §1 (IPv4-in-IPv4 protocol number 4).
        """

        self.assertIs(
            IPPROTO_IPIP,
            IpProto.IP4,
            msg="IPPROTO_IPIP must alias IpProto.IP4 (Linux parity, RFC 2003).",
        )
        self.assertEqual(
            int(IPPROTO_IPIP),
            4,
            msg="IPPROTO_IPIP must serialize to IANA value 4 (RFC 2003).",
        )

    def test__socket__ipproto_aliases(self) -> None:
        """
        Ensure every remaining BSD-style 'IPPROTO_*' alias exported by
        'pytcp.runtime.socket' points at the matching 'IpProto' enum member.
        Any drift would silently break the BSD-API surface.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self.assertIs(
            IPPROTO_ICMP,
            IpProto.ICMP4,
            msg="IPPROTO_ICMP must alias IpProto.ICMP4.",
        )
        self.assertIs(
            IPPROTO_ICMP4,
            IpProto.ICMP4,
            msg="IPPROTO_ICMP4 must alias IpProto.ICMP4.",
        )
        self.assertIs(
            IPPROTO_TCP,
            IpProto.TCP,
            msg="IPPROTO_TCP must alias IpProto.TCP.",
        )
        self.assertIs(
            IPPROTO_UDP,
            IpProto.UDP,
            msg="IPPROTO_UDP must alias IpProto.UDP.",
        )
        self.assertIs(
            IPPROTO_IPV6,
            IpProto.IP6,
            msg="IPPROTO_IPV6 must alias IpProto.IP6.",
        )
        self.assertIs(
            IPPROTO_IP6,
            IpProto.IP6,
            msg="IPPROTO_IP6 must alias IpProto.IP6.",
        )
        self.assertIs(
            IPPROTO_ICMPV6,
            IpProto.ICMP6,
            msg="IPPROTO_ICMPV6 must alias IpProto.ICMP6.",
        )
        self.assertIs(
            IPPROTO_ICMP6,
            IpProto.ICMP6,
            msg="IPPROTO_ICMP6 must alias IpProto.ICMP6.",
        )
        self.assertIs(
            IPPROTO_RAW,
            IpProto.RAW,
            msg="IPPROTO_RAW must alias IpProto.RAW.",
        )


class TestSocketFactory(TestCase):
    """
    The 'socket.__new__' factory dispatch tests.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress socket construction log output so the factory-path
        tests can exercise concrete subclass '__init__' without the
        real 'log()' writing to the shared stderr stream. Isolate the
        process-wide packet-socket registry so the PACKET factory cases
        (which self-register on construction) do not leak into the
        global tap target.
        """

        self.enterContext(patch("pytcp.runtime.socket.raw__socket.log"))
        self.enterContext(patch("pytcp.runtime.socket.tcp__socket.log"))
        self.enterContext(patch("pytcp.runtime.socket.udp__socket.log"))
        self.enterContext(patch("pytcp.runtime.socket.packet__socket.log"))

        from pytcp import stack

        prior = stack.packet_sockets.snapshot()
        stack.packet_sockets.clear()

        def _restore() -> None:
            stack.packet_sockets.clear()
            for sock in prior:
                stack.packet_sockets.register(sock)

        self.addCleanup(_restore)

    def test__socket__stream_creates_tcp_socket(self) -> None:
        """
        Ensure passing 'SocketType.STREAM' returns a 'TcpSocket' instance
        for both the implicit-protocol and explicit 'IpProto.TCP'
        branches of the '__new__' match statement.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        implicit = socket(family=AddressFamily.INET4, type=SocketType.STREAM)
        explicit = socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            protocol=IpProto.TCP,
        )

        self.assertIsInstance(
            implicit,
            TcpSocket,
            msg="socket(STREAM) with implicit protocol must dispatch to TcpSocket.",
        )
        self.assertIsInstance(
            explicit,
            TcpSocket,
            msg="socket(STREAM, IpProto.TCP) must dispatch to TcpSocket.",
        )

    def test__socket__dgram_creates_udp_socket(self) -> None:
        """
        Ensure passing 'SocketType.DGRAM' returns a 'UdpSocket' instance
        for both the implicit-protocol and explicit 'IpProto.UDP'
        branches.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        implicit = socket(family=AddressFamily.INET4, type=SocketType.DGRAM)
        explicit = socket(
            family=AddressFamily.INET4,
            type=SocketType.DGRAM,
            protocol=IpProto.UDP,
        )

        self.assertIsInstance(
            implicit,
            UdpSocket,
            msg="socket(DGRAM) with implicit protocol must dispatch to UdpSocket.",
        )
        self.assertIsInstance(
            explicit,
            UdpSocket,
            msg="socket(DGRAM, IpProto.UDP) must dispatch to UdpSocket.",
        )

    def test__socket__raw_ipv4_creates_raw_socket(self) -> None:
        """
        Ensure passing 'AddressFamily.INET4' together with
        'SocketType.RAW' returns a 'RawSocket' instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = socket(
            family=AddressFamily.INET4,
            type=SocketType.RAW,
            protocol=IpProto.ICMP4,
        )
        self.assertIsInstance(
            s,
            RawSocket,
            msg="socket(INET4, RAW, ICMP4) must dispatch to RawSocket.",
        )

    def test__socket__raw_ipv6_creates_raw_socket(self) -> None:
        """
        Ensure passing 'AddressFamily.INET6' together with
        'SocketType.RAW' returns a 'RawSocket' instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = socket(
            family=AddressFamily.INET6,
            type=SocketType.RAW,
            protocol=IpProto.ICMP6,
        )
        self.assertIsInstance(
            s,
            RawSocket,
            msg="socket(INET6, RAW, ICMP6) must dispatch to RawSocket.",
        )

    def test__socket__packet_raw_creates_packet_socket(self) -> None:
        """
        Ensure passing 'AddressFamily.PACKET' together with
        'SocketType.RAW' returns a 'PacketSocket' instance, both with an
        explicit ethertype and with the implicit (None) protocol that
        defaults to the ETH_P_ALL capture filter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        explicit = socket(
            family=AddressFamily.PACKET,
            type=SocketType.RAW,
            protocol=ETH_P_ALL,
        )
        implicit = socket(family=AddressFamily.PACKET, type=SocketType.RAW)

        self.assertIsInstance(
            explicit,
            PacketSocket,
            msg="socket(PACKET, RAW, ETH_P_ALL) must dispatch to PacketSocket.",
        )
        self.assertIsInstance(
            implicit,
            PacketSocket,
            msg="socket(PACKET, RAW) with implicit protocol must dispatch to PacketSocket.",
        )

    def test__socket__packet_stream_raises_value_error(self) -> None:
        """
        Ensure 'socket(AF_PACKET, SOCK_STREAM)' is rejected with
        'ValueError' — the PACKET family supports SOCK_RAW only in the
        Phase-0 skeleton (the cooked SOCK_DGRAM variant lands later).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as context:
            socket(family=AddressFamily.PACKET, type=SocketType.STREAM)

        self.assertIn(
            "Invalid socket",
            str(context.exception),
            msg="socket(PACKET, STREAM) must raise ValueError naming the rejected tuple.",
        )

    def test__socket__packet_dgram_raises_value_error(self) -> None:
        """
        Ensure 'socket(AF_PACKET, SOCK_DGRAM)' is rejected with
        'ValueError' in the Phase-0 skeleton — the cooked link-layer
        variant is deferred.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as context:
            socket(family=AddressFamily.PACKET, type=SocketType.DGRAM)

        self.assertIn(
            "Invalid socket",
            str(context.exception),
            msg="socket(PACKET, DGRAM) must raise ValueError in the Phase-0 skeleton.",
        )

    def test__socket__invalid_combination_raises(self) -> None:
        """
        Ensure an unsupported (family, type, protocol) triple raises
        'ValueError' with a message that names the rejected values.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        with self.assertRaises(ValueError) as context:
            socket(
                family=AddressFamily.INET4,
                type=SocketType.STREAM,
                protocol=IpProto.UDP,
            )

        self.assertIn(
            "Invalid socket",
            str(context.exception),
            msg="socket.__new__ must raise ValueError naming the rejected tuple.",
        )

    def test__socket__stream_with_ipproto_ip_sentinel_creates_tcp(self) -> None:
        """
        Ensure passing the BSD 'IPPROTO_IP' (= 0) sentinel as the
        protocol arg routes 'SocketType.STREAM' to 'TcpSocket' just
        like the implicit-protocol path. BSD 'socket(AF_INET,
        SOCK_STREAM, IPPROTO_IP)' must yield a TCP socket because
        IPPROTO_IP is the "default protocol" marker, not an IANA
        next-header value.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            protocol=IPPROTO_IP,
        )
        self.assertIsInstance(
            s,
            TcpSocket,
            msg="socket(STREAM, IPPROTO_IP) must dispatch to TcpSocket per BSD default-protocol semantics.",
        )

    def test__socket__dgram_with_ipproto_ip_sentinel_creates_udp(self) -> None:
        """
        Ensure 'socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)' yields a
        'UdpSocket' — the BSD default-protocol sentinel selects UDP
        for the DGRAM socket type.

        Reference: RFC 768 (UDP user interface).
        """

        s = socket(
            family=AddressFamily.INET4,
            type=SocketType.DGRAM,
            protocol=IPPROTO_IP,
        )
        self.assertIsInstance(
            s,
            UdpSocket,
            msg="socket(DGRAM, IPPROTO_IP) must dispatch to UdpSocket per BSD default-protocol semantics.",
        )

    def test__socket__raw_without_protocol_raises_eprotonosupport(self) -> None:
        """
        Ensure 'socket(AF_INET, SOCK_RAW)' with no explicit protocol
        raises 'OSError(EPROTONOSUPPORT)' — the Linux behavior. Raw
        sockets cannot use the BSD "default protocol" sentinel because
        a raw socket without a chosen protocol is undefined; Linux's
        'sys_socket' returns 'EPROTONOSUPPORT' for this case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            socket(family=AddressFamily.INET4, type=SocketType.RAW)
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="socket(RAW) with no protocol must raise OSError(EPROTONOSUPPORT).",
        )

    def test__socket__raw_with_ipproto_ip_sentinel_raises_eprotonosupport(self) -> None:
        """
        Ensure 'socket(AF_INET, SOCK_RAW, IPPROTO_IP)' (raw with the
        BSD default-protocol sentinel) errors with 'EPROTONOSUPPORT',
        same as no-protocol — the sentinel cannot select a default for
        raw sockets.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            socket(
                family=AddressFamily.INET4,
                type=SocketType.RAW,
                protocol=IPPROTO_IP,
            )
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="socket(RAW, IPPROTO_IP) must raise OSError(EPROTONOSUPPORT).",
        )

    def test__socket__raw_ipv6_without_protocol_raises_eprotonosupport(self) -> None:
        """
        Ensure 'socket(AF_INET6, SOCK_RAW)' with no explicit protocol
        also raises 'OSError(EPROTONOSUPPORT)' — symmetric with the
        IPv4 case, matching Linux behavior.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            socket(family=AddressFamily.INET6, type=SocketType.RAW)
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="socket(INET6, RAW) with no protocol must raise OSError(EPROTONOSUPPORT).",
        )

    def test__socket__subclass_bypasses_factory(self) -> None:
        """
        Ensure calling '__new__' on a concrete subclass skips the
        dispatch table — the derived-class constructor must get an
        instance of its own type rather than a re-dispatched pick.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = TcpSocket.__new__(TcpSocket)
        self.assertIsInstance(
            instance,
            TcpSocket,
            msg="TcpSocket.__new__ must bypass the dispatch table and return a TcpSocket.",
        )


class _StubSocket(socket):
    """
    Minimal concrete 'socket' stub used to exercise the base-class
    methods ('__str__', '__enter__', '__exit__', properties, and the
    'NotImplementedError' placeholders) without running the complex
    '__init__' of the real Tcp/Udp/Raw subclasses.
    """

    def __init__(
        self,
        *,
        address_family: AddressFamily = AddressFamily.INET4,
        socket_type: SocketType = SocketType.STREAM,
        ip_proto: IpProto = IpProto.TCP,
        local_ip_address: Ip4Address | Ip6Address = Ip4Address("10.0.0.1"),
        remote_ip_address: Ip4Address | Ip6Address = Ip4Address("10.0.0.2"),
        local_port: int = 1024,
        remote_port: int = 2048,
    ) -> None:
        """
        Populate the private attributes the base class reads through
        its property surface.
        """

        self._address_family = address_family
        self._socket_type = socket_type
        self._ip_proto = ip_proto
        self._local_ip_address = local_ip_address
        self._remote_ip_address = remote_ip_address
        self._local_port = local_port
        self._remote_port = remote_port
        # Default-off so the dual-stack presentation wrapper is a
        # no-op in this base-class test path. Set by the listener-
        # fork on accepted children of AF_INET6 V6ONLY=0 listeners
        # (H3 Phase 3c).
        self._dual_stack = False


class TestSocketStringification(TestCase):
    """
    The 'socket.__str__' / 'socket.__repr__' formatting tests.
    """

    def test__socket__str_format(self) -> None:
        """
        Ensure '__str__' formats the socket as the canonical
        'family/type/proto/local_ip/local_port/remote_ip/remote_port'
        seven-field slash-separated log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket()

        self.assertEqual(
            str(s),
            "INET4/STREAM/TCP/10.0.0.1/1024/10.0.0.2/2048",
            msg="socket.__str__ must produce the canonical seven-field log string.",
        )

    def test__socket__repr_matches_str(self) -> None:
        """
        Ensure '__repr__' delegates to '__str__' so debug and log
        output carry the same representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket()
        self.assertEqual(
            repr(s),
            str(s),
            msg="socket.__repr__ must return the same string as socket.__str__.",
        )


class TestSocketContextManager(TestCase):
    """
    The 'socket.__enter__' / 'socket.__exit__' context-manager tests.
    """

    def test__socket__context_manager_returns_self(self) -> None:
        """
        Ensure entering the runtime context yields the socket object
        itself so the 'with' binding matches the receiver.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket()
        with s as bound:
            self.assertIs(
                bound,
                s,
                msg="socket.__enter__ must return the same socket object.",
            )

    def test__socket__context_manager_exit_is_silent(self) -> None:
        """
        Ensure '__exit__' is a no-op that does not suppress or raise
        anything — clean exit must not mask caller-side exceptions and
        must not signal suppression.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket()
        try:
            s.__exit__(RuntimeError, RuntimeError("boom"), None)
        except Exception as exc:  # pragma: no cover - fail path
            self.fail(f"socket.__exit__ must not raise; got {exc!r}.")


class TestSocketProperties(TestCase):
    """
    The 'socket' read-only property surface tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a canonical stub socket for every property assertion.
        """

        self._socket = _StubSocket(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.DGRAM,
            ip_proto=IpProto.UDP,
            local_ip_address=Ip6Address("2001:db8::1"),
            remote_ip_address=Ip6Address("2001:db8::2"),
            local_port=53,
            remote_port=5353,
        )

    def test__socket__socket_id_reflects_state(self) -> None:
        """
        Ensure 'socket_id' assembles a 'SocketId' from every private
        attribute that defines the socket tuple. This is the key used
        in 'stack.sockets'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.DGRAM,
            local_address=Ip6Address("2001:db8::1"),
            local_port=53,
            remote_address=Ip6Address("2001:db8::2"),
            remote_port=5353,
        )
        self.assertEqual(
            self._socket.socket_id,
            expected,
            msg="socket.socket_id must be built from every private tuple attribute.",
        )

    def test__socket__internal_property_getters(self) -> None:
        """
        Ensure the 'address_family', 'socket_type', 'ip_proto',
        'local_ip_address', 'remote_ip_address', 'local_port',
        'remote_port' properties each return the matching private
        attribute.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            self._socket.address_family,
            AddressFamily.INET6,
            msg="socket.address_family must return the '_address_family' attribute.",
        )
        self.assertIs(
            self._socket.socket_type,
            SocketType.DGRAM,
            msg="socket.socket_type must return the '_socket_type' attribute.",
        )
        self.assertIs(
            self._socket.ip_proto,
            IpProto.UDP,
            msg="socket.ip_proto must return the '_ip_proto' attribute.",
        )
        self.assertEqual(
            self._socket.local_ip_address,
            Ip6Address("2001:db8::1"),
            msg="socket.local_ip_address must return the '_local_ip_address' attribute.",
        )
        self.assertEqual(
            self._socket.remote_ip_address,
            Ip6Address("2001:db8::2"),
            msg="socket.remote_ip_address must return the '_remote_ip_address' attribute.",
        )
        self.assertEqual(
            self._socket.local_port,
            53,
            msg="socket.local_port must return the '_local_port' attribute.",
        )
        self.assertEqual(
            self._socket.remote_port,
            5353,
            msg="socket.remote_port must return the '_remote_port' attribute.",
        )

    def test__socket__bsd_api_property_aliases(self) -> None:
        """
        Ensure the BSD-compatible 'family', 'type', 'proto' properties
        return the same values as their internal counterparts.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            self._socket.family,
            self._socket.address_family,
            msg="socket.family alias must match socket.address_family.",
        )
        self.assertIs(
            self._socket.type,
            self._socket.socket_type,
            msg="socket.type alias must match socket.socket_type.",
        )
        self.assertIs(
            self._socket.proto,
            self._socket.ip_proto,
            msg="socket.proto alias must match socket.ip_proto.",
        )


class TestSocketGetSockName(TestCase):
    """
    The 'socket.getsockname' / 'socket.getpeername' tests.
    """

    def test__socket__getsockname_returns_str_port_tuple(self) -> None:
        """
        Ensure 'getsockname()' returns a '(str_ip, port)' tuple matching
        the BSD API shape, with the IP address stringified.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket(
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=1024,
        )
        self.assertEqual(
            s.getsockname(),
            ("10.0.0.1", 1024),
            msg="socket.getsockname() must return a (str_ip, port) tuple.",
        )

    def test__socket__getpeername_returns_str_port_tuple(self) -> None:
        """
        Ensure 'getpeername()' returns a '(remote_str_ip, remote_port)'
        tuple matching the BSD socket API contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket(
            remote_ip_address=Ip4Address("10.0.0.2"),
            local_port=1024,
            remote_port=2048,
        )
        self.assertEqual(
            s.getpeername(),
            ("10.0.0.2", 2048),
            msg="socket.getpeername() must return a (remote_str_ip, remote_port) tuple.",
        )

    def test__socket__getpeername_unconnected_raises_enotconn(self) -> None:
        """
        Ensure 'getpeername()' on an unconnected socket (zero remote port)
        raises 'OSError(ENOTCONN)', matching the BSD / stdlib
        'getpeername(2)' contract — asyncio's datagram transport relies on
        this to distinguish an unconnected socket (use 'sendto') from a
        connected one (use 'send').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = _StubSocket(remote_port=0)

        with self.assertRaises(OSError) as ctx:
            s.getpeername()

        self.assertEqual(
            ctx.exception.errno,
            errno.ENOTCONN,
            msg="An unconnected socket's getpeername() must raise OSError(ENOTCONN).",
        )


class TestSocketPlaceholders(TestCase):
    """
    The 'socket' BSD API placeholder tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a stub socket for exercising the abstract placeholders.
        """

        self._socket = _StubSocket()

    def test__socket__bind_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'bind' placeholder raises
        'NotImplementedError'. Concrete subclasses must override it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.bind(("10.0.0.1", 1024))

    def test__socket__connect_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'connect' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.connect(("10.0.0.2", 2048))

    def test__socket__send_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'send' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.send(b"data")

    def test__socket__recv_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'recv' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.recv()

    def test__socket__recv_mv_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'recv__mv' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.recv__mv()

    def test__socket__close_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'close' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.close()

    def test__socket__listen_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'listen' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.listen()

    def test__socket__accept_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'accept' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.accept()

    def test__socket__sendto_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'sendto' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.sendto(b"data", ("10.0.0.2", 2048))

    def test__socket__recvfrom_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'recvfrom' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.recvfrom()

    def test__socket__recvfrom_mv_raises_not_implemented(self) -> None:
        """
        Ensure the base-class 'recvfrom__mv' placeholder raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            self._socket.recvfrom__mv()


class _FdSocket(socket):
    """
    Minimal concrete 'socket' subclass that calls 'super().__init__()'
    to exercise the base-class file-descriptor backing without the
    full Tcp/Udp/Raw runtime — used by the fileno / signal / drain
    tests below.
    """

    def __init__(self) -> None:
        """
        Allocate the base-class IO runtime and leave every other
        attribute unset; the fileno-side surface is independent of
        the address tuple.
        """

        super().__init__()


class TestSocketFileno(TestCase):
    """
    The 'socket.fileno' / read-readiness signal-and-drain tests.
    """

    @override
    def setUp(self) -> None:
        """
        Allocate a fresh '_FdSocket' and register cleanup so its OS
        file descriptor never leaks between tests.
        """

        self._socket = _FdSocket()
        self.addCleanup(self._socket._close_io_runtime)

    def test__socket__fileno_returns_non_negative_int(self) -> None:
        """
        Ensure 'fileno()' returns a non-negative integer file
        descriptor that 'select.select' / 'selectors.DefaultSelector'
        can consume, matching POSIX socket FD semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()

        self.assertIsInstance(
            fd,
            int,
            msg="socket.fileno() must return an int matching the POSIX FD shape.",
        )
        self.assertGreaterEqual(
            fd,
            0,
            msg="socket.fileno() must return a non-negative file descriptor.",
        )

    def test__socket__fileno_is_unique_per_socket_instance(self) -> None:
        """
        Ensure two distinct sockets each get their own OS file
        descriptor — the eventfd backing 'fileno()' must not be
        shared across instances.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        other = _FdSocket()
        self.addCleanup(other._close_io_runtime)

        self.assertNotEqual(
            self._socket.fileno(),
            other.fileno(),
            msg="Each socket instance must get its own backing fd.",
        )

    def test__socket__fileno_initially_not_select_ready(self) -> None:
        """
        Ensure a freshly-constructed socket is not reported readable
        by 'select.select' before any data-arrived signal has been
        delivered. A spurious initial-ready bit would loop async
        frameworks immediately.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="A fresh socket must not be reported readable by select.select.",
        )

    def test__socket__signal_readable_makes_fileno_select_ready(self) -> None:
        """
        Ensure '_signal_readable()' flips the eventfd into the
        readable state so a subsequent 'select.select' returns
        the fd as ready.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._signal_readable()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="_signal_readable() must mark the fd as select-readable.",
        )

    def test__socket__drain_readable_clears_select_ready(self) -> None:
        """
        Ensure '_drain_readable()' returns the eventfd to the
        not-readable state after a prior signal — selector callers
        rely on this transition to stop firing once the queue empties.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._signal_readable()
        self._socket._drain_readable()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="_drain_readable() must return the fd to the not-readable state.",
        )

    def test__socket__drain_readable_is_idempotent(self) -> None:
        """
        Ensure '_drain_readable()' is safe to call when the eventfd
        is already drained — the per-call 'EAGAIN' from a zero
        counter must be swallowed silently so consumers don't have to
        track ready-state themselves.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._drain_readable()
        self._socket._drain_readable()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="Repeated _drain_readable() on an empty eventfd must remain a no-op.",
        )

    def test__socket__signal_then_drain_round_trip(self) -> None:
        """
        Ensure a signal-then-drain cycle returns to the not-ready
        state and a fresh signal flips it readable again — the round
        trip is the core selector-integration contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._signal_readable()
        self._socket._drain_readable()
        self._socket._signal_readable()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="signal -> drain -> signal must leave the fd select-readable.",
        )

    def test__socket__close_io_runtime_closes_underlying_fd(self) -> None:
        """
        Ensure '_close_io_runtime()' closes the OS-level eventfd so
        the descriptor is no longer valid for further syscalls. The
        BSD socket lifecycle requires 'close()' to release the
        kernel resource.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()
        self._socket._close_io_runtime()

        with self.assertRaises(OSError) as context:
            fcntl.fcntl(fd, fcntl.F_GETFD)

        self.assertEqual(
            context.exception.errno,
            errno.EBADF,
            msg="After _close_io_runtime() the fd must be closed (EBADF on syscall).",
        )

    def test__socket__close_io_runtime_is_idempotent(self) -> None:
        """
        Ensure repeated '_close_io_runtime()' calls do not raise —
        the cleanup helper is invoked from teardown paths that may
        also fire from explicit 'close()', and double-close on a
        recycled fd would be a real bug.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._close_io_runtime()
        self._socket._close_io_runtime()

    def test__socket__signal_after_close_is_noop(self) -> None:
        """
        Ensure '_signal_readable()' on a closed socket does not raise.
        A stack-thread producer racing with an application close()
        must never crash the producer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._close_io_runtime()
        self._socket._signal_readable()

    def test__socket__drain_after_close_is_noop(self) -> None:
        """
        Ensure '_drain_readable()' on a closed socket does not raise —
        symmetric with the signal-after-close guarantee.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket._close_io_runtime()
        self._socket._drain_readable()


class TestSocketBlocking(TestCase):
    """
    The 'socket.setblocking' / 'socket.getblocking' tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh '_FdSocket' for the blocking-flag matrix and
        register cleanup of its eventfd.
        """

        self._socket = _FdSocket()
        self.addCleanup(self._socket._close_io_runtime)

    def test__socket__getblocking_default_is_true(self) -> None:
        """
        Ensure a freshly-constructed socket reports 'getblocking() ==
        True', matching POSIX 'socket(2)' which returns sockets in
        blocking mode by default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._socket.getblocking(),
            msg="A fresh socket must default to blocking mode (POSIX socket(2)).",
        )

    def test__socket__setblocking_false_then_getblocking_returns_false(self) -> None:
        """
        Ensure 'setblocking(False)' flips the flag so 'getblocking()'
        reports 'False' on a subsequent call.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.setblocking(False)

        self.assertFalse(
            self._socket.getblocking(),
            msg="setblocking(False) must make getblocking() return False.",
        )

    def test__socket__setblocking_true_then_getblocking_returns_true(self) -> None:
        """
        Ensure 'setblocking(True)' restores the default after a prior
        'setblocking(False)' so apps can toggle modes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.setblocking(False)
        self._socket.setblocking(True)

        self.assertTrue(
            self._socket.getblocking(),
            msg="setblocking(True) after False must restore blocking mode.",
        )

    def test__socket__setblocking_round_trips_through_getblocking(self) -> None:
        """
        Ensure repeated 'setblocking' / 'getblocking' calls preserve
        the most recently set value, with no stale state between
        toggles.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (False, True, False, True, False):
            self._socket.setblocking(value)
            self.assertEqual(
                self._socket.getblocking(),
                value,
                msg=f"setblocking({value}) must round-trip through getblocking().",
            )


class TestSocketDnsHelpers(TestCase):
    """
    The 'pytcp.runtime.socket' DNS-helper re-export tests.
    """

    def test__socket__getaddrinfo_is_stdlib_re_export(self) -> None:
        """
        Ensure 'pytcp.runtime.socket.getaddrinfo' is the same callable as
        CPython's stdlib 'socket.getaddrinfo' so apps calling
        'pytcp.runtime.socket.getaddrinfo(...)' get real DNS resolution.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import socket as _stdlib

        from pytcp.runtime import socket as pytcp_socket

        self.assertIs(
            pytcp_socket.getaddrinfo,
            _stdlib.getaddrinfo,
            msg="pytcp.runtime.socket.getaddrinfo must be the stdlib getaddrinfo callable.",
        )

    def test__socket__gethostbyname_is_stdlib_re_export(self) -> None:
        """
        Ensure 'pytcp.runtime.socket.gethostbyname' is the stdlib symbol.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import socket as _stdlib

        from pytcp.runtime import socket as pytcp_socket

        self.assertIs(
            pytcp_socket.gethostbyname,
            _stdlib.gethostbyname,
            msg="pytcp.runtime.socket.gethostbyname must be the stdlib gethostbyname callable.",
        )

    def test__socket__getnameinfo_is_stdlib_re_export(self) -> None:
        """
        Ensure 'pytcp.runtime.socket.getnameinfo' is the stdlib symbol.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import socket as _stdlib

        from pytcp.runtime import socket as pytcp_socket

        self.assertIs(
            pytcp_socket.getnameinfo,
            _stdlib.getnameinfo,
            msg="pytcp.runtime.socket.getnameinfo must be the stdlib getnameinfo callable.",
        )


class TestSocketInaddrConstants(TestCase):
    """
    The 'pytcp.runtime.socket' INADDR_* constant tests.
    """

    def test__socket__inaddr_any_is_zero(self) -> None:
        """
        Ensure 'INADDR_ANY' equals 0, matching '<arpa/inet.h>'
        and CPython's stdlib 'socket.INADDR_ANY'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import INADDR_ANY

        self.assertEqual(
            INADDR_ANY,
            0,
            msg="INADDR_ANY must equal 0 per <arpa/inet.h>.",
        )

    def test__socket__inaddr_loopback_is_127_0_0_1(self) -> None:
        """
        Ensure 'INADDR_LOOPBACK' equals 0x7f000001 (127.0.0.1).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import INADDR_LOOPBACK

        self.assertEqual(
            INADDR_LOOPBACK,
            0x7F000001,
            msg="INADDR_LOOPBACK must equal 0x7f000001 (127.0.0.1).",
        )

    def test__socket__inaddr_broadcast_is_all_ones(self) -> None:
        """
        Ensure 'INADDR_BROADCAST' equals 0xffffffff
        (255.255.255.255).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.runtime.socket import INADDR_BROADCAST

        self.assertEqual(
            INADDR_BROADCAST,
            0xFFFFFFFF,
            msg="INADDR_BROADCAST must equal 0xffffffff (255.255.255.255).",
        )
