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
This module contains tests for the AF_PACKET raw link-layer socket
('PacketSocket') Phase-0 skeleton — construction, ethertype / ifindex
defaults, and the log-string representation.

pytcp/tests/unit/runtime/socket/test__runtime__socket__packet__socket.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast, override
from unittest import TestCase
from unittest.mock import patch

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from pytcp import stack
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import PacketHandlerL2
from pytcp.runtime.socket import (
    ETH_P_ALL,
    ETH_P_ARP,
    ETH_P_IP,
    AddressFamily,
    PacketType,
    SocketType,
)
from pytcp.runtime.socket.packet__metadata import PacketMetadata
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


class TestPacketSocket(TestCase):
    """
    The AF_PACKET 'PacketSocket' skeleton + RX-side tests.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress packet-socket construction log output and isolate the
        process-wide packet-socket registry (snapshot, clear, restore)
        so register-on-construct does not leak across tests.
        """

        self.enterContext(patch("pytcp.runtime.socket.packet__socket.log"))
        prior = stack.packet_sockets.snapshot()
        stack.packet_sockets.clear()

        def _restore() -> None:
            stack.packet_sockets.clear()
            for sock in prior:
                stack.packet_sockets.register(sock)

        self.addCleanup(_restore)

    def _make(self, *, protocol: EtherType | int | None = None) -> PacketSocket:
        """
        Build a 'PacketSocket' and register its close for cleanup (which
        unregisters it from the registry and releases its eventfd).
        """

        sock = PacketSocket(
            family=AddressFamily.PACKET,
            type=SocketType.RAW,
            protocol=protocol,
        )
        self.addCleanup(sock.close)
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__packet_socket__family_and_type(self) -> None:
        """
        Ensure a 'PacketSocket' reports the PACKET address family and the
        RAW socket type through the base-class property surface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make()

        self.assertIs(
            sock.address_family,
            AddressFamily.PACKET,
            msg="PacketSocket.address_family must be AddressFamily.PACKET.",
        )
        self.assertIs(
            sock.socket_type,
            SocketType.RAW,
            msg="PacketSocket.socket_type must be SocketType.RAW.",
        )

    def test__packet_socket__default_protocol_is_eth_p_all(self) -> None:
        """
        Ensure constructing a 'PacketSocket' with no protocol defaults
        its ethertype filter to ETH_P_ALL (capture-all) and leaves it
        unbound from any interface (ifindex 0).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make()

        self.assertEqual(
            sock.ethertype,
            ETH_P_ALL,
            msg="A PacketSocket with no protocol must default to the ETH_P_ALL filter.",
        )
        self.assertEqual(
            sock.ifindex,
            0,
            msg="A freshly-constructed PacketSocket must be unbound (ifindex 0).",
        )

    def test__packet_socket__explicit_ethertype(self) -> None:
        """
        Ensure an explicit ethertype protocol is stored verbatim as the
        socket's capture / delivery filter.

        Reference: RFC 826 (ARP ethertype 0x0806).
        """

        sock = self._make(protocol=ETH_P_ARP)

        self.assertEqual(
            sock.ethertype,
            EtherType.ARP,
            msg="PacketSocket must store the supplied ethertype filter verbatim.",
        )

    def test__packet_socket__str_format(self) -> None:
        """
        Ensure '__str__' renders the canonical
        'PACKET/RAW/<ethertype>/if<ifindex>' log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)

        self.assertEqual(
            str(sock),
            "PACKET/RAW/0x0806/if0",
            msg="PacketSocket.__str__ must render the canonical link-socket log string.",
        )

    def test__packet_socket__rejects_non_raw_type(self) -> None:
        """
        Ensure constructing a 'PacketSocket' with a non-RAW socket type
        is rejected — the Phase-0 skeleton supports SOCK_RAW only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            PacketSocket(
                family=AddressFamily.PACKET,
                type=SocketType.DGRAM,
                protocol=ETH_P_ALL,
            )

    def test__packet_socket__registers_on_construct(self) -> None:
        """
        Ensure a packet socket registers itself in the process-wide
        registry at construction — Linux starts capturing matching
        frames the moment 'socket(AF_PACKET, ...)' returns, before any
        bind.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)

        self.assertIn(
            sock,
            stack.packet_sockets.snapshot(),
            msg="A PacketSocket must register itself in stack.packet_sockets on construction.",
        )

    def test__packet_socket__close_unregisters(self) -> None:
        """
        Ensure closing a packet socket removes it from the registry so
        the RX tap stops delivering to it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)

        sock.close()

        self.assertNotIn(
            sock,
            stack.packet_sockets.snapshot(),
            msg="close() must unregister the packet socket from stack.packet_sockets.",
        )

    def test__packet_socket__recv_returns_queued_frame(self) -> None:
        """
        Ensure 'recv' returns the raw bytes of a frame previously
        delivered to the socket via 'process_packet'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)
        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06payload"
        sock.process_packet(PacketMetadata(frame=frame, sockaddr_ll=SockAddrLl(ifindex=1, ethertype=ETH_P_ARP)))

        self.assertEqual(
            sock.recv(),
            frame,
            msg="recv() must return the raw bytes of the queued frame.",
        )

    def test__packet_socket__recvfrom_returns_frame_and_sockaddr(self) -> None:
        """
        Ensure 'recvfrom' returns the frame bytes paired with the
        originating 'sockaddr_ll' describing the arrival interface,
        ethertype, packet type, and source MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)
        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06payload"
        sockaddr = SockAddrLl(
            ifindex=1,
            ethertype=ETH_P_ARP,
            pkttype=PacketType.PACKET_BROADCAST,
            mac=MacAddress("02:00:00:00:00:91"),
        )
        sock.process_packet(PacketMetadata(frame=frame, sockaddr_ll=sockaddr))

        data, addr = sock.recvfrom()

        self.assertEqual(data, frame, msg="recvfrom() must return the raw frame bytes.")
        self.assertEqual(addr, sockaddr, msg="recvfrom() must return the originating sockaddr_ll.")

    def test__packet_socket__recv_truncates_to_bufsize(self) -> None:
        """
        Ensure 'recv(bufsize)' truncates the returned frame to 'bufsize'
        bytes, matching POSIX recv(2) on SOCK_RAW.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)
        frame = b"0123456789"
        sock.process_packet(PacketMetadata(frame=frame, sockaddr_ll=SockAddrLl()))

        self.assertEqual(
            sock.recv(4),
            b"0123",
            msg="recv(bufsize) must truncate the frame to bufsize bytes.",
        )

    def test__packet_socket__recv_nonblocking_empty_raises_eagain(self) -> None:
        """
        Ensure a non-blocking 'recv' on an empty queue raises
        'BlockingIOError(EAGAIN)' rather than blocking.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        sock = self._make(protocol=ETH_P_ARP)
        sock.setblocking(False)

        with self.assertRaises(BlockingIOError) as context:
            sock.recv()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="A non-blocking recv on an empty queue must raise BlockingIOError(EAGAIN).",
        )

    def test__packet_socket__bind_sets_ifindex_and_ethertype(self) -> None:
        """
        Ensure 'bind' scopes the socket to the address ifindex AND sets
        the ethertype filter from the address — the SockAddrLl fully
        describes the binding (Linux sll_protocol takes effect on bind),
        so binding an ARP-filtered socket with the default ETH_P_ALL
        address widens it back to capture-all.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        table[1] = cast(PacketHandlerL2, SimpleNamespace(_ifindex=1))
        self.enterContext(patch.object(stack, "interfaces", table))

        sock = self._make(protocol=ETH_P_ARP)
        sock.bind(SockAddrLl(ifindex=1, ethertype=ETH_P_IP))

        self.assertEqual(sock.ifindex, 1, msg="bind must scope the socket to the address ifindex.")
        self.assertEqual(sock.ethertype, EtherType.IP4, msg="bind must set the ethertype filter from the address.")

    def test__packet_socket__bind_ifindex_zero_means_all_interfaces(self) -> None:
        """
        Ensure binding with ifindex 0 is accepted without an interface
        lookup — it scopes the socket to all interfaces (the unbound
        default).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)
        sock.bind(SockAddrLl(ifindex=0, ethertype=ETH_P_ALL))

        self.assertEqual(sock.ifindex, 0, msg="bind(ifindex=0) must scope the socket to all interfaces.")

    def test__packet_socket__bind_unknown_ifindex_raises_enodev(self) -> None:
        """
        Ensure binding to an ifindex with no registered interface raises
        'OSError(ENODEV)'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        self.enterContext(patch.object(stack, "interfaces", InterfaceTable()))
        sock = self._make(protocol=ETH_P_ARP)

        with self.assertRaises(OSError) as context:
            sock.bind(SockAddrLl(ifindex=7))

        self.assertEqual(
            context.exception.errno,
            errno.ENODEV,
            msg="bind to an unregistered ifindex must raise OSError(ENODEV).",
        )
