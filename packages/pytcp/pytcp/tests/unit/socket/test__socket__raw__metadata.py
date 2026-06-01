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
This module contains tests for the 'RawMetadata' class that carries
packet context from the IP parser to a 'RawSocket'.

pytcp/tests/unit/socket/test__socket__raw__metadata.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.socket_id import SocketId


class TestRawMetadataIp4(TestCase):
    """
    The 'RawMetadata' IPv4 socket_ids dispatch tests.
    """

    def setUp(self) -> None:
        """
        Build a canonical IPv4 raw-metadata envelope carrying an ICMP4
        payload.
        """

        self._md = RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=b"payload",
        )

    def test__raw_metadata__stores_fields(self) -> None:
        """
        Ensure every constructor argument is stored verbatim on the
        instance, including the optional raw-data and tracker fields.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            self._md.ip__ver,
            IpVersion.IP4,
            msg="RawMetadata must store 'ip__ver' verbatim.",
        )
        self.assertEqual(
            self._md.ip__local_address,
            Ip4Address("10.0.0.1"),
            msg="RawMetadata must store 'ip__local_address' verbatim.",
        )
        self.assertEqual(
            self._md.ip__remote_address,
            Ip4Address("10.0.0.2"),
            msg="RawMetadata must store 'ip__remote_address' verbatim.",
        )
        self.assertIs(
            self._md.ip__proto,
            IpProto.ICMP4,
            msg="RawMetadata must store 'ip__proto' verbatim.",
        )
        self.assertEqual(
            self._md.raw__data,
            b"payload",
            msg="RawMetadata must store 'raw__data' verbatim.",
        )
        self.assertIsNone(
            self._md.tracker,
            msg="RawMetadata must default 'tracker' to None when not supplied.",
        )

    def test__raw_metadata__socket_ids_ip4(self) -> None:
        """
        Ensure 'socket_ids' for an IPv4 raw envelope enumerates the
        connected, local-bound, and fully-wildcard candidates (most
        specific first) so a RAW socket bound with an unspecified local
        and/or remote address is matched, mirroring the UDP demux. The
        '0' remote port mirrors the raw-socket convention that there is
        no L4 port.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = [
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.RAW,
                local_address=Ip4Address("10.0.0.1"),
                local_port=int(IpProto.ICMP4),
                remote_address=Ip4Address("10.0.0.2"),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.RAW,
                local_address=Ip4Address("10.0.0.1"),
                local_port=int(IpProto.ICMP4),
                remote_address=Ip4Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.RAW,
                local_address=Ip4Address(),
                local_port=int(IpProto.ICMP4),
                remote_address=Ip4Address(),
                remote_port=0,
            ),
        ]
        self.assertEqual(
            self._md.socket_ids,
            expected,
            msg="RawMetadata.socket_ids must enumerate connected, local-bound, and wildcard IPv4 RAW SocketIds.",
        )


class TestRawMetadataIp6(TestCase):
    """
    The 'RawMetadata' IPv6 socket_ids dispatch tests.
    """

    def test__raw_metadata__socket_ids_ip6(self) -> None:
        """
        Ensure 'socket_ids' for an IPv6 raw envelope enumerates the
        connected, local-bound, and fully-wildcard candidates (most
        specific first) with 'AddressFamily.INET6', so a RAW socket
        bound with an unspecified local and/or remote address is
        matched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = RawMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
            ip__proto=IpProto.ICMP6,
        )

        expected = [
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.RAW,
                local_address=Ip6Address("2001:db8::1"),
                local_port=int(IpProto.ICMP6),
                remote_address=Ip6Address("2001:db8::2"),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.RAW,
                local_address=Ip6Address("2001:db8::1"),
                local_port=int(IpProto.ICMP6),
                remote_address=Ip6Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.RAW,
                local_address=Ip6Address(),
                local_port=int(IpProto.ICMP6),
                remote_address=Ip6Address(),
                remote_port=0,
            ),
        ]
        self.assertEqual(
            md.socket_ids,
            expected,
            msg="RawMetadata.socket_ids must enumerate connected, local-bound, and wildcard IPv6 RAW SocketIds.",
        )


class TestRawMetadataDefaults(TestCase):
    """
    The 'RawMetadata' default-value tests.
    """

    def test__raw_metadata__raw_data_defaults_to_empty(self) -> None:
        """
        Ensure 'raw__data' defaults to an empty 'bytes()' when the
        caller does not supply it. This matters for socket lookups
        that only care about the envelope, not the payload.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
        )
        self.assertEqual(
            md.raw__data,
            bytes(),
            msg="RawMetadata.raw__data must default to an empty 'bytes()'.",
        )

    def test__raw_metadata__is_frozen(self) -> None:
        """
        Ensure 'RawMetadata' is immutable so the parser -> socket
        envelope cannot be mutated mid-dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
        )
        with self.assertRaises(FrozenInstanceError):
            md.raw__data = b"reassigned"  # type: ignore[misc]
