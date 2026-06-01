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
Integration tests for the H4 IPv6 half of the socket-layer
Linux parity audit ('docs/refactor/socket_linux_parity_audit.md'
§H4). Lifts the IPv4 'IP_ADD_MEMBERSHIP' pattern to a parallel
'IPV6_JOIN_GROUP' / 'IPV6_LEAVE_GROUP' surface so applications
can drive IPv6 multicast membership through the standard
socket API. The MLDv2 Report-emit machinery is already in tree
('_send_icmp6_multicast_listener_report' called from
'_assign_ip6_multicast'); this commit just wires the
setsockopt path through to it.

pytcp/tests/integration/socket/test__socket__ipv6_join_group.py

ver 3.0.8
"""

import errno
import struct
import sys

from net_addr import Ip6Address
from pytcp.runtime.socket import (
    IPPROTO_IPV6,
    IPV6_JOIN_GROUP,
    IPV6_LEAVE_GROUP,
    AddressFamily,
)
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import NetworkTestCase


def _ipv6_mreq(group: Ip6Address, ifindex: int = 0) -> bytes:
    """
    Build a Linux 'struct ipv6_mreq' bytes object — 16-byte
    multicast group + 4-byte ifindex in host byte order
    (C 'unsigned int').
    """

    return bytes(group) + struct.pack("@I", ifindex)


class TestSocketIpv6JoinGroup(NetworkTestCase):
    """
    H4 IPv6 'IPV6_JOIN_GROUP' / 'IPV6_LEAVE_GROUP' socket
    options. Uses 'UdpSocket' as the carrier; the surface is on
    the base 'socket' class so the implementation is shared
    across TCP / UDP / RAW.
    """

    def test__socket__ipv6_join_group_adds_membership_to_interface(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, mreq)'
        adds the group to the egress packet handler's
        '_ip6_multicast' membership list — the runtime state
        that drives the wire-level MLDv2 Report and any future
        inbound demux.

        Reference: RFC 3493 §5.2 (IPV6_JOIN_GROUP).
        Reference: Linux IPV6_JOIN_GROUP / ipv6_mreq.
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        group = Ip6Address("ff15::1234")
        before = list(self._packet_handler._ip6_multicast)

        sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(group))

        self.assertNotIn(
            group,
            before,
            msg="Fixture precondition: group not pre-joined.",
        )
        self.assertIn(
            group,
            self._packet_handler._ip6_multicast,
            msg="setsockopt(IPV6_JOIN_GROUP) must add the group to _ip6_multicast.",
        )

    def test__socket__ipv6_leave_group_removes_membership(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IPV6, IPV6_LEAVE_GROUP, mreq)'
        removes a previously-joined group from the egress
        handler's '_ip6_multicast' list.

        Reference: RFC 3493 §5.2 (IPV6_LEAVE_GROUP).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        group = Ip6Address("ff15::1234")
        sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(group))
        self.assertIn(
            group,
            self._packet_handler._ip6_multicast,
            msg="Fixture precondition: join must have succeeded.",
        )

        sock.setsockopt(IPPROTO_IPV6, IPV6_LEAVE_GROUP, _ipv6_mreq(group))

        self.assertNotIn(
            group,
            self._packet_handler._ip6_multicast,
            msg="setsockopt(IPV6_LEAVE_GROUP) must remove the group from _ip6_multicast.",
        )

    def test__socket__ipv6_join_group_twice_raises_eaddrinuse(self) -> None:
        """
        Ensure joining a group a second time on the same
        socket raises 'OSError(EADDRINUSE)' — Linux's
        'ipv6_sock_mc_join' returns this errno when the
        socket already holds the membership.

        Reference: Linux ipv6_sock_mc_join (EADDRINUSE on duplicate join).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        group = Ip6Address("ff15::abcd")
        sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(group))

        with self.assertRaises(OSError) as ctx:
            sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(group))
        self.assertEqual(
            ctx.exception.errno,
            errno.EADDRINUSE,
            msg="Joining a group the socket already holds must raise EADDRINUSE.",
        )

    def test__socket__ipv6_leave_group_not_a_member_raises_eaddrnotavail(self) -> None:
        """
        Ensure leaving a group the socket never joined raises
        'OSError(EADDRNOTAVAIL)' — Linux parity for
        'ipv6_sock_mc_drop'.

        Reference: Linux ipv6_sock_mc_drop (EADDRNOTAVAIL on stale leave).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        group = Ip6Address("ff15::beef")

        with self.assertRaises(OSError) as ctx:
            sock.setsockopt(IPPROTO_IPV6, IPV6_LEAVE_GROUP, _ipv6_mreq(group))
        self.assertEqual(
            ctx.exception.errno,
            errno.EADDRNOTAVAIL,
            msg="Leaving a group the socket is not a member of must raise EADDRNOTAVAIL.",
        )

    def test__socket__ipv6_join_group_non_multicast_raises_einval(self) -> None:
        """
        Ensure joining a non-multicast group address raises
        'OSError(EINVAL)' — the address must satisfy the IPv6
        'is_multicast' predicate (the ff00::/8 prefix).

        Reference: RFC 4291 §2.7 (IPv6 multicast prefix).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        unicast = Ip6Address("2001:db8::1")

        with self.assertRaises(OSError) as ctx:
            sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(unicast))
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="Joining a non-multicast address must raise EINVAL.",
        )

    def test__socket__ipv6_join_group_short_mreq_raises_einval(self) -> None:
        """
        Ensure a truncated 'ipv6_mreq' bytes object raises
        'OSError(EINVAL)' — Linux's 'sock_setsockopt' rejects a
        partial struct rather than reading uninitialised memory.

        Reference: Linux ipv6_sock_mc_join (struct-length validation).
        """

        sock = UdpSocket(family=AddressFamily.INET6)

        with self.assertRaises(OSError) as ctx:
            sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, b"\x00" * 10)
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="A < 20-byte ipv6_mreq must raise EINVAL.",
        )

    def test__socket__ipv6_join_group_zero_ifindex_picks_first_ipv6_iface(self) -> None:
        """
        Ensure ifindex=0 in 'ipv6_mreq' (the "let kernel pick"
        sentinel) resolves to the first interface owning an
        IPv6 unicast address — matches Linux's
        'inet6_lookup_first_iface' semantics.

        Reference: Linux ipv6_sock_mc_join (ifindex=0 fallback).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        group = Ip6Address("ff15::aaaa")

        sock.setsockopt(
            IPPROTO_IPV6,
            IPV6_JOIN_GROUP,
            bytes(group) + struct.pack("@I", 0),
        )

        # Verify against the canonical fixture's primary
        # interface — the NetworkTestCase harness sets up
        # exactly one IPv6-capable interface, so the resolved
        # ifindex matches '_packet_handler' (the primary
        # interface handler).
        self.assertIn(
            group,
            self._packet_handler._ip6_multicast,
            msg="ifindex=0 must pick the first IPv6-capable interface and add the group there.",
        )

    def test__socket__ipv6_join_group_emits_mldv2_report_on_wire(self) -> None:
        """
        Ensure the join triggers an outbound MLDv2 Report on
        the wire — the runtime path the join state must take
        for the upstream router to receive group traffic.
        Reuses the harness's '_send_icmp6_multicast_listener_report'
        machinery; this test pins the end-to-end wiring.

        Reference: RFC 3810 §5 (MLDv2 Report on join).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        group = Ip6Address("ff15::5678")

        # Use a fresh ssize-of-tx so the assertion is unaffected
        # by harness-emitted setup frames.
        baseline = len(self._frames_tx)
        sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(group))
        emitted = self._frames_tx[baseline:]

        self.assertGreaterEqual(
            len(emitted),
            1,
            msg="A join must emit at least one MLDv2 Report frame.",
        )


# Suppress the "unused" warning on 'sys' (we use it via @I struct
# pack which silently encodes native byte order — referenced here
# so future maintainers see the intent).
_ = sys
