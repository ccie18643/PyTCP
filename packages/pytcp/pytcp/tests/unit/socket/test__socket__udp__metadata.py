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
This module contains tests for the 'UdpMetadata' class that carries
packet context from the UDP parser to a 'UdpSocket'.

pytcp/tests/unit/socket/test__socket__udp__metadata.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address, IpVersion
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.socket_id import SocketId
from pytcp.socket.udp__metadata import UdpMetadata


class TestUdpMetadataFields(TestCase):
    """
    The 'UdpMetadata' field-storage tests.
    """

    def test__udp_metadata__stores_fields(self) -> None:
        """
        Ensure 'UdpMetadata' stores every constructor argument verbatim
        and defaults 'udp__data' / 'tracker' to their documented empty
        values when omitted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
        )

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
        self.assertEqual(md.udp__local_port, 1234, msg="udp__local_port must be stored verbatim.")
        self.assertEqual(md.udp__remote_port, 5678, msg="udp__remote_port must be stored verbatim.")
        self.assertEqual(
            bytes(md.udp__data),
            b"",
            msg="udp__data must default to an empty memoryview.",
        )
        self.assertIsNone(md.tracker, msg="tracker must default to None.")

    def test__udp_metadata__is_frozen(self) -> None:
        """
        Ensure 'UdpMetadata' is immutable so the parser -> socket
        envelope cannot be mutated mid-dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
        )
        with self.assertRaises(FrozenInstanceError):
            md.udp__local_port = 9999  # type: ignore[misc]


class TestUdpMetadataSocketIdsGeneric(TestCase):
    """
    The 'UdpMetadata.socket_ids' generic-dispatch tests (non-DHCP cases).
    """

    def test__udp_metadata__socket_ids_ip4_generic(self) -> None:
        """
        Ensure a non-DHCP IPv4 datagram produces three candidate socket
        IDs matching, in order, an exact (local, remote) socket, a
        semi-wild socket with unspecified remote, and a fully wild
        socket with unspecified local and remote.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
        )
        expected = [
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                local_address=Ip4Address("10.0.0.1"),
                local_port=1234,
                remote_address=Ip4Address("10.0.0.2"),
                remote_port=5678,
            ),
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                local_address=Ip4Address("10.0.0.1"),
                local_port=1234,
                remote_address=Ip4Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                local_address=Ip4Address(),
                local_port=1234,
                remote_address=Ip4Address(),
                remote_port=0,
            ),
        ]
        self.assertEqual(
            md.socket_ids,
            expected,
            msg="UdpMetadata.socket_ids must return the three IPv4 candidate IDs in the documented order.",
        )

    def test__udp_metadata__socket_ids_ip6_generic(self) -> None:
        """
        Ensure a non-DHCPv6 IPv6 datagram produces the same three
        candidate shape as the IPv4 generic path, with IPv6
        unspecified addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
            udp__local_port=1234,
            udp__remote_port=5678,
        )
        expected = [
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.DGRAM,
                local_address=Ip6Address("2001:db8::1"),
                local_port=1234,
                remote_address=Ip6Address("2001:db8::2"),
                remote_port=5678,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.DGRAM,
                local_address=Ip6Address("2001:db8::1"),
                local_port=1234,
                remote_address=Ip6Address(),
                remote_port=0,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.DGRAM,
                local_address=Ip6Address(),
                local_port=1234,
                remote_address=Ip6Address(),
                remote_port=0,
            ),
        ]
        self.assertEqual(
            md.socket_ids,
            expected,
            msg="UdpMetadata.socket_ids must return the three IPv6 candidate IDs in the documented order.",
        )


class TestUdpMetadataSocketIdsDhcp(TestCase):
    """
    The 'UdpMetadata.socket_ids' DHCP-client special-case tests.
    """

    def test__udp_metadata__socket_ids_dhcp4(self) -> None:
        """
        Ensure an IPv4 datagram with local port 68 and remote port 67
        resolves to the two canonical DHCPv4 client socket IDs — one
        keyed on the sender's unicast address (the RENEWING-state
        reply path) and one on the limited broadcast
        '255.255.255.255' (the INIT and REBINDING reply paths). The
        DHCPv4 client socket always binds to the anonymous local
        '0.0.0.0' so both entries share that local address.

        Reference: RFC 2131 §4.4.5 (RENEW unicast / REBIND broadcast).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=68,
            udp__remote_port=67,
        )
        expected = [
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                local_address=Ip4Address(),
                local_port=68,
                remote_address=Ip4Address("10.0.0.2"),
                remote_port=67,
            ),
            SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                local_address=Ip4Address(),
                local_port=68,
                remote_address=Ip4Address("255.255.255.255"),
                remote_port=67,
            ),
        ]
        self.assertEqual(
            md.socket_ids,
            expected,
            msg=(
                "UdpMetadata.socket_ids must emit two DHCPv4 client IDs "
                "(sender-unicast for RENEW, '255.255.255.255' for INIT/REBIND) "
                "for port 68->67 envelopes."
            ),
        )

    def test__udp_metadata__socket_ids_dhcp6(self) -> None:
        """
        Ensure an IPv6 datagram with local port 546 and remote port 547
        resolves to the two canonical DHCPv6 client socket IDs — one
        for each multicast group (ff02::1:2 and ff02::1:3) that
        DHCPv6 servers listen on.

        Reference: RFC 8415 §7.1 (DHCPv6 multicast destinations).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
            udp__local_port=546,
            udp__remote_port=547,
        )
        expected = [
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.DGRAM,
                local_address=Ip6Address(),
                local_port=546,
                remote_address=Ip6Address("ff02::1:2"),
                remote_port=547,
            ),
            SocketId(
                address_family=AddressFamily.INET6,
                socket_type=SocketType.DGRAM,
                local_address=Ip6Address(),
                local_port=546,
                remote_address=Ip6Address("ff02::1:3"),
                remote_port=547,
            ),
        ]
        self.assertEqual(
            md.socket_ids,
            expected,
            msg="UdpMetadata.socket_ids must emit both DHCPv6 client IDs (ff02::1:2 and ff02::1:3).",
        )

    def test__udp_metadata__socket_ids_dhcp4_wrong_version_falls_through(self) -> None:
        """
        Ensure a DHCP-port pair on the wrong IP version (e.g. 68->67
        over IPv6) falls through to the generic three-candidate shape
        rather than the DHCPv4 short-circuit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        md = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=Ip6Address("2001:db8::1"),
            ip__remote_address=Ip6Address("2001:db8::2"),
            udp__local_port=68,
            udp__remote_port=67,
        )

        self.assertEqual(
            len(md.socket_ids),
            3,
            msg=(
                "UdpMetadata.socket_ids must fall through to the generic dispatch "
                "when the IP version does not match the DHCP short-circuit."
            ),
        )
