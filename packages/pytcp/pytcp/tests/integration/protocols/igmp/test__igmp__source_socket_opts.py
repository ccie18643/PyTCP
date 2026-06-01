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
This module contains integration tests for the RFC 3678 / RFC 3376 §3.1
source-filter socket options (IP_ADD_SOURCE_MEMBERSHIP,
IP_DROP_SOURCE_MEMBERSHIP, IP_BLOCK_SOURCE, IP_UNBLOCK_SOURCE) — their
effect on the per-socket and merged per-interface (§3.2) filters and the
Linux 'ip_mc_source' errno mapping.

pytcp/tests/integration/protocols/igmp/test__igmp__source_socket_opts.py

ver 3.0.8
"""

import errno
from typing import override

from net_addr import Ip4Address
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.runtime.socket import (
    AF_INET,
    IP_ADD_MEMBERSHIP,
    IP_ADD_SOURCE_MEMBERSHIP,
    IP_BLOCK_SOURCE,
    IP_DROP_SOURCE_MEMBERSHIP,
    IP_UNBLOCK_SOURCE,
    IPPROTO_IP,
    SOCK_DGRAM,
    socket,
)
from pytcp.tests.lib.network_testcase import NetworkTestCase

_GROUP = Ip4Address("239.1.1.1")
_S1 = Ip4Address("10.0.0.1")
_S2 = Ip4Address("10.0.0.2")

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / socket log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _mreq(group: Ip4Address = _GROUP, interface: str = "0.0.0.0") -> bytes:
    """Pack an 8-byte ip_mreq (imr_multiaddr + imr_interface)."""

    return bytes(group) + bytes(Ip4Address(interface))


def _mreq_source(source: Ip4Address, *, group: Ip4Address = _GROUP, interface: str = "0.0.0.0") -> bytes:
    """Pack a 12-byte ip_mreq_source (imr_multiaddr + imr_sourceaddr + imr_interface)."""

    return bytes(group) + bytes(source) + bytes(Ip4Address(interface))


class TestIgmpSourceSocketOptions(NetworkTestCase):
    """
    The RFC 3678 / RFC 3376 §3.1 source-filter socket-option tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and open two datagram sockets for the options.
        """

        super().setUp()
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(self._socket.close)
        self._socket_b = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(self._socket_b.close)

    def _interface_filter(self) -> Ip4MulticastFilter:
        """Return the merged per-interface filter for the test group."""

        return self._packet_handler._ip4_multicast_filters[_GROUP]

    def test__add_source__creates_include_filter_and_joins(self) -> None:
        """
        Ensure IP_ADD_SOURCE_MEMBERSHIP joins the group with an INCLUDE
        filter carrying the requested source.

        Reference: RFC 3376 §3.1 (INCLUDE-mode source list).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        self.assertIn(_GROUP, self._packet_handler._ip4_multicast)
        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset({_S1})),
            msg="IP_ADD_SOURCE_MEMBERSHIP must yield an INCLUDE{source} interface filter.",
        )

    def test__add_source__second_source_unions_into_include(self) -> None:
        """
        Ensure a second IP_ADD_SOURCE_MEMBERSHIP adds its source to the
        socket's INCLUDE list.

        Reference: RFC 3376 §3.1 (INCLUDE-mode source list grows by source).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S2))

        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset({_S1, _S2})),
            msg="A second IP_ADD_SOURCE_MEMBERSHIP must union its source into the INCLUDE list.",
        )

    def test__drop_source__removes_source_and_leaves_when_empty(self) -> None:
        """
        Ensure IP_DROP_SOURCE_MEMBERSHIP removes a source and, when it
        empties the INCLUDE list, leaves the group entirely.

        Reference: RFC 3376 §3.1 (INCLUDE{} deletes the membership).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S2))
        self._socket.setsockopt(IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset({_S2})),
            msg="IP_DROP_SOURCE_MEMBERSHIP must remove only the named source.",
        )

        self._socket.setsockopt(IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, _mreq_source(_S2))
        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="Dropping the last INCLUDE source must leave the group.",
        )

    def test__block_source__on_any_source_join_excludes_source(self) -> None:
        """
        Ensure IP_BLOCK_SOURCE on an any-source (EXCLUDE{}) membership
        adds the source to the EXCLUDE list.

        Reference: RFC 3376 §3.1 (EXCLUDE-mode source list).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())
        self._socket.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, _mreq_source(_S1))

        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE, frozenset({_S1})),
            msg="IP_BLOCK_SOURCE must add the source to the EXCLUDE list.",
        )

    def test__unblock_source__removes_blocked_source(self) -> None:
        """
        Ensure IP_UNBLOCK_SOURCE removes a previously blocked source from
        the EXCLUDE list.

        Reference: RFC 3376 §3.1 (EXCLUDE-mode source list shrinks by source).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())
        self._socket.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, _mreq_source(_S1))
        self._socket.setsockopt(IPPROTO_IP, IP_UNBLOCK_SOURCE, _mreq_source(_S1))

        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE, frozenset()),
            msg="IP_UNBLOCK_SOURCE must remove the source from the EXCLUDE list.",
        )

    def test__add_source__on_exclude_membership_raises_einval(self) -> None:
        """
        Ensure IP_ADD_SOURCE_MEMBERSHIP on a group already held in
        EXCLUDE (any-source) mode raises OSError(EINVAL).

        Reference: RFC 3376 §3.1 (a socket holds one filter mode per group).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self.assertEqual(ctx.exception.errno, errno.EINVAL, msg="A mode conflict must raise EINVAL.")

    def test__block_source__on_include_membership_raises_einval(self) -> None:
        """
        Ensure IP_BLOCK_SOURCE on a group held in INCLUDE mode raises
        OSError(EINVAL).

        Reference: RFC 3376 §3.1 (a socket holds one filter mode per group).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, _mreq_source(_S2))
        self.assertEqual(ctx.exception.errno, errno.EINVAL, msg="A mode conflict must raise EINVAL.")

    def test__block_source__without_join_raises_einval(self) -> None:
        """
        Ensure IP_BLOCK_SOURCE with no prior any-source join raises
        OSError(EINVAL).

        Reference: RFC 3376 §3.1 (blocking presupposes an EXCLUDE membership).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, _mreq_source(_S1))
        self.assertEqual(ctx.exception.errno, errno.EINVAL, msg="BLOCK without a membership must raise EINVAL.")

    def test__drop_source__non_member_raises_eaddrnotavail(self) -> None:
        """
        Ensure IP_DROP_SOURCE_MEMBERSHIP on a group this socket never
        joined raises OSError(EADDRNOTAVAIL).

        Reference: RFC 3376 §3.1 (no per-socket record to modify).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self.assertEqual(
            ctx.exception.errno, errno.EADDRNOTAVAIL, msg="Dropping a non-member must raise EADDRNOTAVAIL."
        )

    def test__drop_source__unknown_source_raises_eaddrnotavail(self) -> None:
        """
        Ensure IP_DROP_SOURCE_MEMBERSHIP for a source not in the INCLUDE
        list raises OSError(EADDRNOTAVAIL).

        Reference: RFC 3376 §3.1 (source not present in the per-socket list).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, _mreq_source(_S2))
        self.assertEqual(
            ctx.exception.errno, errno.EADDRNOTAVAIL, msg="Dropping an unlisted source must raise EADDRNOTAVAIL."
        )

    def test__merge__two_include_sockets_union_sources(self) -> None:
        """
        Ensure two sockets each in INCLUDE mode merge to a per-interface
        INCLUDE filter whose source list is the union of theirs.

        Reference: RFC 3376 §3.2 (all-INCLUDE merge is the source union).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self._socket_b.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S2))

        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset({_S1, _S2})),
            msg="Two INCLUDE sockets must merge to the union of their sources.",
        )

    def test__merge__exclude_plus_include_yields_exclude(self) -> None:
        """
        Ensure an any-source (EXCLUDE{}) socket merged with an INCLUDE
        socket yields a per-interface EXCLUDE{} filter — the EXCLUDE
        socket wants every source, so nothing is filtered.

        Reference: RFC 3376 §3.2 (any-EXCLUDE merge is EXCLUDE, intersection minus includes).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())
        self._socket_b.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        self.assertEqual(
            self._interface_filter(),
            Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE, frozenset()),
            msg="An EXCLUDE{} socket plus an INCLUDE socket must merge to EXCLUDE{}.",
        )

    def test__close__releases_source_filter(self) -> None:
        """
        Ensure closing a socket releases the source filter it held, so
        the group leaves the interface when it was the last contributor.

        Reference: RFC 3376 §3.2 (interface state follows the live socket set).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self.assertIn(_GROUP, self._packet_handler._ip4_multicast)

        self._socket.close()
        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="Closing the last contributing socket must leave the group.",
        )

    def test__source_opt__short_mreq_source_raises_einval(self) -> None:
        """
        Ensure a source-filter option with a too-short ip_mreq_source
        raises OSError(EINVAL).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_S1) + bytes(_GROUP))
        self.assertEqual(ctx.exception.errno, errno.EINVAL, msg="A short ip_mreq_source must raise EINVAL.")

    def test__source_opt__non_multicast_group_raises_einval(self) -> None:
        """
        Ensure a source-filter option naming a non-multicast group raises
        OSError(EINVAL).

        Reference: RFC 1112 §4 (membership is for multicast groups).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.setsockopt(
                IPPROTO_IP,
                IP_ADD_SOURCE_MEMBERSHIP,
                _mreq_source(_S1, group=Ip4Address("192.0.2.1")),
            )
        self.assertEqual(ctx.exception.errno, errno.EINVAL, msg="A non-multicast group must raise EINVAL.")
