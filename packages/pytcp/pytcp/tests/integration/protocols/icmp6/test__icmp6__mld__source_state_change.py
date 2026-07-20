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
Integration tests for the RFC 3810 §5.2 / §6.1 source-bearing MLDv2
state-change Reports — a per-socket source-filter change (the
MCAST_JOIN_SOURCE_GROUP family) emits an MLDv2 Report carrying the
ALLOW_NEW_SOURCES / BLOCK_OLD_SOURCES / CHANGE_TO_INCLUDE /
CHANGE_TO_EXCLUDE difference record with the affected source list. The
IPv6 analogue of the shipped IGMPv3 source-state-change track.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__source_state_change.py

ver 3.0.8
"""

import struct
from typing import override

from net_addr import Ip6Address
from net_proto import Icmp6Mld2MulticastAddressRecordType as RecordType
from pytcp import stack
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
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip6Address("ff15::1234")
_S1 = Ip6Address("2001:db8::a")
_S2 = Ip6Address("2001:db8::b")
_AF_INET6 = 10

# Ethernet(14) + IPv6(40) + HBH(8) — the ICMPv6 message starts here.
_OFFSET_ICMP6 = 14 + 40 + 8
_OFFSET_MLD2_NR_RECORDS = _OFFSET_ICMP6 + 6
_OFFSET_MLD2_FIRST_RECORD = _OFFSET_ICMP6 + 8

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / socket log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _ipv6_mreq(group: Ip6Address, ifindex: int = 0) -> bytes:
    """Pack a 20-byte 'ipv6_mreq' (16-byte group + 4-byte ifindex)."""

    return bytes(group) + struct.pack("@I", ifindex)


def _group_source_req(group: Ip6Address, source: Ip6Address, *, ifindex: int = 0) -> bytes:
    """Pack a 264-byte Linux 'struct group_source_req' (group + source)."""

    gsr = bytearray(264)
    struct.pack_into("@I", gsr, 0, ifindex)
    struct.pack_into("@H", gsr, 8, _AF_INET6)
    gsr[16:32] = bytes(group)
    struct.pack_into("@H", gsr, 136, _AF_INET6)
    gsr[144:160] = bytes(source)
    return bytes(gsr)


def _records(frame: bytes) -> list[tuple[int, frozenset[Ip6Address]]]:
    """
    Decode the (type, source-set) of every Multicast Address Record in an
    MLDv2 Report frame. Assumes zero aux-data per record (the shape a
    state-change uses): each record is type(1) aux(1) nr_sources(2)
    group(16) + nr_sources * 16.
    """

    nr_records = int.from_bytes(frame[_OFFSET_MLD2_NR_RECORDS : _OFFSET_MLD2_NR_RECORDS + 2], "big")
    records: list[tuple[int, frozenset[Ip6Address]]] = []
    pos = _OFFSET_MLD2_FIRST_RECORD
    for _ in range(nr_records):
        record_type = frame[pos]
        nr_sources = int.from_bytes(frame[pos + 2 : pos + 4], "big")
        sources = {Ip6Address(bytes(frame[pos + 20 + i * 16 : pos + 20 + i * 16 + 16])) for i in range(nr_sources)}
        records.append((record_type, frozenset(sources)))
        pos += 20 + nr_sources * 16
    return records


class TestIcmp6MldSourceStateChange(IcmpTestCase):
    """
    The RFC 3810 §5.2 / §6.1 source-bearing MLDv2 state-change Report tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and open two IPv6 datagram sockets.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(self._socket.close)
        self._socket_b = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(self._socket_b.close)

    def _emitted_records(self, op: int, payload: bytes) -> list[tuple[int, frozenset[Ip6Address]]]:
        """Apply a socket option and return the records of the single Report it emits."""

        before = len(self._frames_tx)
        self._socket.setsockopt(IPPROTO_IPV6, op, payload)
        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The state change must emit exactly one Report.")

        return _records(frames[0])

    def test__add_source__fresh_join_emits_allow_new_sources(self) -> None:
        """
        Ensure a first MCAST_JOIN_SOURCE_GROUP emits an ALLOW_NEW_SOURCES
        record for the added source — the non-member INCLUDE{} → INCLUDE{s}
        transition.

        Reference: RFC 3810 §6.1 (INCLUDE(A)→INCLUDE(B) sends ALLOW (B-A)).
        """

        self.assertEqual(
            self._emitted_records(MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1)),
            [(int(RecordType.ALLOW_NEW_SOURCES), frozenset({_S1}))],
            msg="A fresh source join must report ALLOW_NEW_SOURCES for the source.",
        )

    def test__add_source__second_source_emits_allow_for_delta_only(self) -> None:
        """
        Ensure a second MCAST_JOIN_SOURCE_GROUP emits an ALLOW_NEW_SOURCES
        record carrying only the newly added source.

        Reference: RFC 3810 §6.1 (the difference report carries only B-A).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))

        self.assertEqual(
            self._emitted_records(MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S2)),
            [(int(RecordType.ALLOW_NEW_SOURCES), frozenset({_S2}))],
            msg="Adding a second source must report ALLOW_NEW_SOURCES for only that source.",
        )

    def test__drop_source__emits_block_old_sources(self) -> None:
        """
        Ensure MCAST_LEAVE_SOURCE_GROUP on one of several included sources
        emits a BLOCK_OLD_SOURCES record for the removed source.

        Reference: RFC 3810 §6.1 (INCLUDE(A)→INCLUDE(B) sends BLOCK (A-B)).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S2))

        self.assertEqual(
            self._emitted_records(MCAST_LEAVE_SOURCE_GROUP, _group_source_req(_GROUP, _S1)),
            [(int(RecordType.BLOCK_OLD_SOURCES), frozenset({_S1}))],
            msg="Dropping an included source must report BLOCK_OLD_SOURCES for it.",
        )

    def test__block_source__emits_block_old_sources(self) -> None:
        """
        Ensure MCAST_BLOCK_SOURCE on an any-source (EXCLUDE{}) membership
        emits a BLOCK_OLD_SOURCES record for the newly blocked source.

        Reference: RFC 3810 §6.1 (EXCLUDE(A)→EXCLUDE(B) sends BLOCK (B-A)).
        """

        self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))

        self.assertEqual(
            self._emitted_records(MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _S1)),
            [(int(RecordType.BLOCK_OLD_SOURCES), frozenset({_S1}))],
            msg="Blocking a source must report BLOCK_OLD_SOURCES for it.",
        )

    def test__unblock_source__emits_allow_new_sources(self) -> None:
        """
        Ensure MCAST_UNBLOCK_SOURCE emits an ALLOW_NEW_SOURCES record for
        the source restored to reception.

        Reference: RFC 3810 §6.1 (EXCLUDE(A)→EXCLUDE(B) sends ALLOW (A-B)).
        """

        self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
        self._socket.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _S1))

        self.assertEqual(
            self._emitted_records(MCAST_UNBLOCK_SOURCE, _group_source_req(_GROUP, _S1)),
            [(int(RecordType.ALLOW_NEW_SOURCES), frozenset({_S1}))],
            msg="Unblocking a source must report ALLOW_NEW_SOURCES for it.",
        )

    def test__mode_flip_to_exclude__emits_change_to_exclude(self) -> None:
        """
        Ensure an interface filter that flips from INCLUDE to EXCLUDE (an
        any-source socket joining a group held only in INCLUDE mode) emits
        a CHANGE_TO_EXCLUDE record with an empty source list.

        Reference: RFC 3810 §6.1 (INCLUDE(A)→EXCLUDE(B) sends TO_EX (B)).
        Reference: RFC 3810 §4.2 (any EXCLUDE socket makes the interface EXCLUDE).
        """

        self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))

        before = len(self._frames_tx)
        self._socket_b.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
        frames = self._frames_tx[before:]

        self.assertEqual(len(frames), 1, msg="The mode flip must emit one Report.")
        self.assertEqual(
            _records(frames[0]),
            [(int(RecordType.CHANGE_TO_EXCLUDE), frozenset())],
            msg="An INCLUDE→EXCLUDE mode flip must report CHANGE_TO_EXCLUDE.",
        )

    def test__any_source_join_emits_change_to_exclude(self) -> None:
        """
        Ensure a fresh any-source join (IPV6_JOIN_GROUP) emits a
        CHANGE_TO_EXCLUDE record — the non-member INCLUDE{} → EXCLUDE{}
        transition.

        Reference: RFC 3810 §6.1 (a new EXCLUDE membership sends TO_EX).
        """

        self.assertEqual(
            self._emitted_records(IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP)),
            [(int(RecordType.CHANGE_TO_EXCLUDE), frozenset())],
            msg="A fresh any-source join must report CHANGE_TO_EXCLUDE.",
        )
