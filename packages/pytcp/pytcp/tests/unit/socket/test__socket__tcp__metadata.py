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
This module contains tests for the 'TcpMetadata' class that carries
packet context from the TCP parser to a 'TcpSocket' / 'TcpSession'.

pytcp/tests/unit/socket/test__socket__tcp__metadata.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address, IpVersion
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.socket_id import SocketId
from pytcp.socket.tcp__metadata import TcpMetadata


def _make_ip4_metadata(**overrides: object) -> TcpMetadata:
    """
    Build a canonical IPv4 'TcpMetadata' fixture and allow per-test
    overrides via keyword arguments.
    """

    defaults: dict[str, object] = {
        "ip__ver": IpVersion.IP4,
        "ip__local_address": Ip4Address("10.0.0.1"),
        "ip__remote_address": Ip4Address("10.0.0.2"),
        "tcp__local_port": 8080,
        "tcp__remote_port": 44444,
        "tcp__flag_syn": True,
        "tcp__flag_ack": False,
        "tcp__flag_fin": False,
        "tcp__flag_rst": False,
        "tcp__flag_ece": False,
        "tcp__flag_cwr": False,
        "tcp__seq": 1000,
        "tcp__ack": 0,
        "tcp__win": 65535,
        "tcp__wscale": 0,
        "tcp__mss": 1460,
        "tcp__sackperm": False,
        "tcp__sack_blocks": (),
        "tcp__data": memoryview(b""),
        "tracker": None,
    }
    defaults.update(overrides)
    return TcpMetadata(**defaults)  # type: ignore[arg-type]


class TestTcpMetadataFields(TestCase):
    """
    The 'TcpMetadata' field-storage tests.
    """

    def test__tcp_metadata__stores_every_field(self) -> None:
        """
        Ensure 'TcpMetadata' exposes every constructor argument as an
        attribute. The parser -> socket handoff depends on every field
        being available without additional decoding.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = _make_ip4_metadata()

        self.assertIs(md.ip__ver, IpVersion.IP4, msg="ip__ver must be stored verbatim.")
        self.assertEqual(
            md.ip__local_address,
            Ip4Address("10.0.0.1"),
            msg="ip__local_address must be stored verbatim.",
        )
        self.assertEqual(
            md.ip__remote_address,
            Ip4Address("10.0.0.2"),
            msg="ip__remote_address must be stored verbatim.",
        )
        self.assertEqual(md.tcp__local_port, 8080, msg="tcp__local_port must be stored verbatim.")
        self.assertEqual(md.tcp__remote_port, 44444, msg="tcp__remote_port must be stored verbatim.")
        self.assertTrue(md.tcp__flag_syn, msg="tcp__flag_syn must be stored verbatim.")
        self.assertFalse(md.tcp__flag_ack, msg="tcp__flag_ack must be stored verbatim.")
        self.assertEqual(md.tcp__seq, 1000, msg="tcp__seq must be stored verbatim.")
        self.assertEqual(md.tcp__ack, 0, msg="tcp__ack must be stored verbatim.")
        self.assertEqual(md.tcp__win, 65535, msg="tcp__win must be stored verbatim.")
        self.assertEqual(md.tcp__wscale, 0, msg="tcp__wscale must be stored verbatim.")
        self.assertEqual(md.tcp__mss, 1460, msg="tcp__mss must be stored verbatim.")
        self.assertFalse(md.tcp__sackperm, msg="tcp__sackperm must be stored verbatim.")
        self.assertEqual(md.tcp__sack_blocks, (), msg="tcp__sack_blocks must be stored verbatim.")
        self.assertEqual(bytes(md.tcp__data), b"", msg="tcp__data must be stored verbatim.")
        self.assertIsNone(md.tracker, msg="tracker must be stored verbatim.")

    def test__tcp_metadata__is_frozen(self) -> None:
        """
        Ensure 'TcpMetadata' is immutable so the parser -> socket
        envelope cannot be mutated mid-dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = _make_ip4_metadata()
        with self.assertRaises(FrozenInstanceError):
            md.tcp__seq = 42  # type: ignore[misc]


class TestTcpMetadataSocketIdIp4(TestCase):
    """
    The 'TcpMetadata.socket_id' IPv4 tests.
    """

    def test__tcp_metadata__socket_id_ip4(self) -> None:
        """
        Ensure the exact-match 'socket_id' for an IPv4 envelope packs
        (INET4, STREAM, local_ip, local_port, remote_ip, remote_port)
        — the key used to route packets to an established session.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = _make_ip4_metadata()
        expected = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_address=Ip4Address("10.0.0.2"),
            remote_port=44444,
        )
        self.assertEqual(
            md.socket_id,
            expected,
            msg="TcpMetadata.socket_id must build the exact-match IPv4 SocketId.",
        )

    def test__tcp_metadata__listening_socket_ids_ip4(self) -> None:
        """
        Ensure 'listening_socket_ids' for an IPv4 envelope produces
        THREE candidates in order: AF_INET local-specific,
        AF_INET local-unspecified, AND the AF_INET6 wildcard
        ('::') dual-stack pattern that matches a 'V6ONLY = 0'
        IPv6 listener. The AF_INET candidates come first so a
        family-specific listener wins over a dual-stack one
        when both exist on the same port.

        Reference: socket_linux_parity_audit.md §H3 Phase 3b (dual-stack lookup).
        """

        md = _make_ip4_metadata()
        expected = [
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                local_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                remote_address=Ip4Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                local_address=Ip4Address(),
                local_port=8080,
                remote_address=Ip4Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.STREAM,
                local_address=Ip6Address(),
                local_port=8080,
                remote_address=Ip6Address(),
                remote_port=0,
            ),
        ]
        self.assertEqual(
            md.listening_socket_ids,
            expected,
            msg=(
                "IPv4 listening_socket_ids must include the AF_INET6 wildcard "
                "dual-stack pattern as the third candidate."
            ),
        )


class TestTcpMetadataSocketIdIp6(TestCase):
    """
    The 'TcpMetadata.socket_id' IPv6 tests.
    """

    def test__tcp_metadata__socket_id_ip6(self) -> None:
        """
        Ensure the exact-match 'socket_id' for an IPv6 envelope packs
        (INET6, STREAM, ...) with the IPv6 addresses preserved.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = _make_ip4_metadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
        )
        expected = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=Ip6Address("2001:db8::1"),
            local_port=8080,
            remote_address=Ip6Address("2001:db8::2"),
            remote_port=44444,
        )
        self.assertEqual(
            md.socket_id,
            expected,
            msg="TcpMetadata.socket_id must build the exact-match IPv6 SocketId.",
        )

    def test__tcp_metadata__listening_socket_ids_ip6(self) -> None:
        """
        Ensure 'listening_socket_ids' for an IPv6 envelope produces the
        two listener-match candidates with the '::' unspecified IPv6
        remote/wildcard-local addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = _make_ip4_metadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
        )
        expected = [
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.STREAM,
                local_address=Ip6Address("2001:db8::1"),
                local_port=8080,
                remote_address=Ip6Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.STREAM,
                local_address=Ip6Address(),
                local_port=8080,
                remote_address=Ip6Address(),
                remote_port=0,
            ),
        ]
        self.assertEqual(
            md.listening_socket_ids,
            expected,
            msg="TcpMetadata.listening_socket_ids must produce the IPv6 listener candidates.",
        )
