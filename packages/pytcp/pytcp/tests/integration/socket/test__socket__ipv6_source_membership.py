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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the IPv6 protocol-independent multicast
source-filter socket options (RFC 3678 / RFC 3810 §4.1) —
MCAST_JOIN_SOURCE_GROUP / MCAST_LEAVE_SOURCE_GROUP / MCAST_BLOCK_SOURCE /
MCAST_UNBLOCK_SOURCE at IPPROTO_IPV6 level, carrying a 'group_source_req'
struct. The IPv6 analogue of the IPv4 'IP_ADD_SOURCE_MEMBERSHIP' family.

pytcp/tests/integration/socket/test__socket__ipv6_source_membership.py

ver 3.0.10
"""

import errno
import struct
from typing import override

from net_addr import Ip6Address
from pytcp import stack
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.runtime.socket import (
    IPPROTO_IPV6,
    IPV6_JOIN_GROUP,
    MCAST_BLOCK_SOURCE,
    MCAST_JOIN_SOURCE_GROUP,
    MCAST_LEAVE_SOURCE_GROUP,
    MCAST_UNBLOCK_SOURCE,
    AddressFamily,
)
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import NetworkTestCase

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / socket log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


_GROUP = Ip6Address("ff15::1234")
_SRC_A = Ip6Address("2001:db8::a")
_SRC_B = Ip6Address("2001:db8::b")
# Linux OS-level AF_INET6 as it appears in a sockaddr wire struct.
_AF_INET6 = 10


def _ipv6_mreq(group: Ip6Address, ifindex: int = 0) -> bytes:
    """Pack a 20-byte 'ipv6_mreq' (16-byte group + 4-byte ifindex)."""

    return bytes(group) + struct.pack("@I", ifindex)


def _group_source_req(
    group: Ip6Address,
    source: Ip6Address,
    *,
    ifindex: int = 0,
    family: int = _AF_INET6,
) -> bytes:
    """
    Pack a Linux 'struct group_source_req' (264 bytes): uint32
    gsr_interface at 0; sockaddr_storage gsr_group at 8 (sockaddr_in6
    family at 8, addr at 16); sockaddr_storage gsr_source at 136
    (family at 136, addr at 144).
    """

    gsr = bytearray(264)
    struct.pack_into("@I", gsr, 0, ifindex)
    struct.pack_into("@H", gsr, 8, family)
    gsr[16:32] = bytes(group)
    struct.pack_into("@H", gsr, 136, family)
    gsr[144:160] = bytes(source)
    return bytes(gsr)


class TestSocketIpv6SourceMembership(NetworkTestCase):
    """
    The IPv6 MCAST_* source-filter socket-option tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and open an IPv6 datagram socket.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(self._socket.close)

    def test__mcast_join_source_group_materializes_include(self) -> None:
        """
        Ensure MCAST_JOIN_SOURCE_GROUP for one source joins the group in
        INCLUDE mode with exactly that source in the interface filter.

        Reference: RFC 3810 §4.1 (per-socket INCLUDE source list).
        Reference: RFC 3678 §4 (MCAST_JOIN_SOURCE_GROUP).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))

        self.assertEqual(
            self._packet_handler._ip6_multicast_filters[_GROUP],
            Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_SRC_A})),
            msg="A single-source join must materialize INCLUDE{source} on the interface.",
        )

    def test__mcast_join_two_sources_accumulates_include(self) -> None:
        """
        Ensure two MCAST_JOIN_SOURCE_GROUP calls on one socket accumulate
        both sources into the interface INCLUDE filter.

        Reference: RFC 3810 §4.1 (per-socket INCLUDE source list grows).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_B))

        self.assertEqual(
            self._packet_handler._ip6_multicast_filters[_GROUP],
            Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_SRC_A, _SRC_B})),
            msg="Joining a second source must accumulate it into the INCLUDE filter.",
        )

    def test__mcast_leave_last_source_leaves_group(self) -> None:
        """
        Ensure MCAST_LEAVE_SOURCE_GROUP removing the only source in an
        INCLUDE membership leaves the group entirely.

        Reference: RFC 3810 §4.1 (INCLUDE{} delete leaves the group).
        Reference: RFC 3678 §4 (MCAST_LEAVE_SOURCE_GROUP).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_LEAVE_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))

        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip6_multicast,
            msg="Leaving the last INCLUDE source must leave the group.",
        )

    def test__mcast_join_source_on_exclude_membership_raises_einval(self) -> None:
        """
        Ensure MCAST_JOIN_SOURCE_GROUP on a group the socket already holds
        as an any-source (EXCLUDE) membership is a filter-mode conflict
        rejected with EINVAL.

        Reference: RFC 3810 §4.1 (INCLUDE op on an EXCLUDE membership is invalid).
        """

        self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="An INCLUDE join on an EXCLUDE-mode membership must raise EINVAL.",
        )

    def test__mcast_block_source_requires_any_source_join(self) -> None:
        """
        Ensure MCAST_BLOCK_SOURCE with no prior any-source membership is
        rejected with EINVAL — blocking is only meaningful on an
        EXCLUDE-mode (any-source) join.

        Reference: RFC 3810 §4.1 (BLOCK requires an EXCLUDE-mode membership).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _SRC_A))
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="MCAST_BLOCK_SOURCE without a prior any-source join must raise EINVAL.",
        )

    def test__mcast_block_source_after_any_source_join_excludes(self) -> None:
        """
        Ensure MCAST_BLOCK_SOURCE after an any-source join adds the source
        to the interface EXCLUDE filter.

        Reference: RFC 3810 §4.1 (BLOCK adds to the EXCLUDE source list).
        """

        self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _SRC_A))

        self.assertEqual(
            self._packet_handler._ip6_multicast_filters[_GROUP],
            Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE, frozenset({_SRC_A})),
            msg="Blocking a source on an any-source membership must EXCLUDE it.",
        )

    def test__mcast_unblock_source_removes_from_exclude(self) -> None:
        """
        Ensure MCAST_UNBLOCK_SOURCE removes a previously-blocked source
        from the EXCLUDE list, returning the membership to any-source
        (EXCLUDE{}) while keeping the group joined.

        Reference: RFC 3810 §4.1 (UNBLOCK removes from the EXCLUDE source list).
        Reference: RFC 3678 §4 (MCAST_UNBLOCK_SOURCE).
        """

        self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _SRC_A))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_UNBLOCK_SOURCE, _group_source_req(_GROUP, _SRC_A))

        self.assertEqual(
            self._packet_handler._ip6_multicast_filters[_GROUP],
            Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE, frozenset()),
            msg="Unblocking the only blocked source must return the group to EXCLUDE{}.",
        )

    def test__mcast_leave_source_not_a_member_raises_eaddrnotavail(self) -> None:
        """
        Ensure MCAST_LEAVE_SOURCE_GROUP for a group the socket never
        joined raises EADDRNOTAVAIL.

        Reference: RFC 3810 §4.1 (leave of a non-member source is invalid).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_LEAVE_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))
        self.assertEqual(
            ctx.exception.errno,
            errno.EADDRNOTAVAIL,
            msg="Leaving a source on a group the socket does not hold must raise EADDRNOTAVAIL.",
        )

    def test__mcast_source_req_short_raises_einval(self) -> None:
        """
        Ensure a truncated 'group_source_req' bytes object raises EINVAL
        rather than reading past the buffer.

        Reference: Linux ip6_mc_source (struct-length validation).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, b"\x00" * 100)
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="A short group_source_req must raise EINVAL.",
        )

    def test__mcast_source_req_wrong_family_raises_einval(self) -> None:
        """
        Ensure a 'group_source_req' whose sockaddr family is not AF_INET6
        is rejected with EINVAL.

        Reference: Linux ip6_mc_source (sockaddr family validation).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(
                IPPROTO_IPV6,
                MCAST_JOIN_SOURCE_GROUP,
                _group_source_req(_GROUP, _SRC_A, family=2),
            )
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="A non-AF_INET6 group_source_req must raise EINVAL.",
        )

    def test__mcast_close_releases_source_membership(self) -> None:
        """
        Ensure closing a socket releases every IPv6 source-filter
        membership it holds, leaving the group on the interface.

        Reference: RFC 3810 §6.1 (leave on the last contributor drop).
        Reference: Linux ipv6_sock_mc_close (drop memberships on close).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _SRC_A))
        self.assertIn(_GROUP, self._packet_handler._ip6_multicast)

        self._socket.close()

        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip6_multicast,
            msg="Closing the last socket holding a source-filter membership must leave the group.",
        )
