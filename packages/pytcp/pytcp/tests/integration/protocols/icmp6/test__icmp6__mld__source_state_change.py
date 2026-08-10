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

ver 3.0.10
"""

import struct
from typing import override
from unittest.mock import patch

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6Mld2MulticastAddressRecordType as RecordType
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
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
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip6Address("ff15::1234")
_S1 = Ip6Address("2001:db8::a")
_S2 = Ip6Address("2001:db8::b")
_S3 = Ip6Address("2001:db8::c")
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


def _build_mld1_query_frame() -> bytes:
    """
    Build a 24-octet RFC 2710 §3.1 MLDv1 General Query frame (ICMPv6
    type 130 to ff02::1, hop 1, from a router link-local source) — used
    to drive the interface into MLDv1 Host Compatibility Mode.
    """

    body = b"\x27\x10" + b"\x00\x00" + b"\x00" * 16  # MRD=10000ms, ::
    icmp6_no_cksum = b"\x82\x00\x00\x00" + body
    ip6_src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    ip6_dst = bytes.fromhex("ff020000000000000000000000000001")  # ff02::1
    icmp6_len = len(icmp6_no_cksum)
    pseudo = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"
    cksum = inet_cksum(pseudo + icmp6_no_cksum)
    icmp6 = icmp6_no_cksum[:2] + cksum.to_bytes(2, "big") + icmp6_no_cksum[4:]
    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a\x01" + ip6_src + ip6_dst
    ethernet = b"\x33\x33\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x91" + b"\x86\xdd"
    return ethernet + ip6_header + icmp6


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

    def test__within_mode_change__emits_both_allow_and_block(self) -> None:
        """
        Ensure a single within-mode interface-filter change that both
        adds and drops sources (INCLUDE{S1,S2} → INCLUDE{S2,S3}) emits one
        Report carrying both an ALLOW_NEW_SOURCES record for the added
        source and a BLOCK_OLD_SOURCES record for the dropped source.

        Reference: RFC 3810 §6.1 (INCLUDE(A)→INCLUDE(B) sends ALLOW (B-A) and BLOCK (A-B)).
        """

        # Drive the interface filter directly through the handler so a
        # single recompute changes two sources at once (the socket options
        # only mutate one source per call).
        self._packet_handler.mc6_set_socket_filter(
            _GROUP,
            token=1,
            source_filter=Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_S1, _S2})),
        )

        before = len(self._frames_tx)
        self._packet_handler.mc6_set_socket_filter(
            _GROUP,
            token=1,
            source_filter=Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_S2, _S3})),
        )
        frames = self._frames_tx[before:]

        self.assertEqual(len(frames), 1, msg="The within-mode change must emit exactly one Report.")
        self.assertEqual(
            set(_records(frames[0])),
            {
                (int(RecordType.ALLOW_NEW_SOURCES), frozenset({_S3})),
                (int(RecordType.BLOCK_OLD_SOURCES), frozenset({_S1})),
            },
            msg="The Report must carry ALLOW for the added source and BLOCK for the dropped source.",
        )

    def test__emit_mld2_report__empty_records_emits_nothing(self) -> None:
        """
        Ensure emitting an MLDv2 Report with no Multicast Address Records
        sends no frame — an empty state-change is not put on the wire.

        Reference: RFC 3810 §5.2 (a Report with zero records carries no information).
        """

        before = len(self._frames_tx)
        self._packet_handler._icmp6_tx._emit_mld2_report([])

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="An MLDv2 Report with no records must emit nothing.",
        )

    def test__all_nodes__state_change_emits_nothing(self) -> None:
        """
        Ensure a state-change for the permanent all-nodes group ff02::1
        emits nothing — the host never reports its all-nodes membership.

        Reference: RFC 3810 §6 (the all-nodes group ff02::1 is never reported).
        """

        before = len(self._frames_tx)
        self._packet_handler._send_mld_state_change(
            Ip6Address("ff02::1"),
            old=Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE),
            new=Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE),
        )

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="A state-change for ff02::1 must emit nothing.",
        )

    def test__mldv1_mode__source_only_change_emits_nothing(self) -> None:
        """
        Ensure that while the interface is in MLDv1 Host Compatibility
        Mode a source-only change within a still-joined membership
        (blocking a source on an any-source join) emits nothing — MLDv1
        has no source concept, so only reception-edge changes are visible.

        Reference: RFC 3810 §8.3.1 (MLDv1 Reports carry no source list).
        """

        with sysctl.override("mld.version", 1):
            self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))

            before = len(self._frames_tx)
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_BLOCK_SOURCE, _group_source_req(_GROUP, _S1))

            self.assertEqual(
                len(self._frames_tx[before:]),
                0,
                msg="A source-only change in MLDv1 mode must emit no Report.",
            )


class TestIcmp6MldStateChangeRetransmit(IcmpTestCase):
    """
    The RFC 3810 §6.1 MLDv2 state-change robustness-retransmit tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and open an IPv6 datagram socket.
        """

        super().setUp()
        self._socket = UdpSocket(family=AddressFamily.INET6)
        self.addCleanup(self._socket.close)
        # The all-nodes multicast MAC (ff02::1) so the inbound MLDv1
        # General Query frame passes the L2 RX filter.
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))

    def test__retransmit__carries_source_list(self) -> None:
        """
        Ensure the robustness retransmission of a source state-change
        Report carries the same source-bearing record as the immediate
        Report.

        Reference: RFC 3810 §6.1 (state-change Report retransmitted RV-1 times with its records).
        """

        with sysctl.override("mld.robustness", 2):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__icmp6__tx.random.randint",
                    return_value=200,
                )
            )
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))

            tx = self._advance(ms=200)
            self.assertEqual(len(tx), 1, msg="One robustness retransmit must fire at the chosen delay.")
            self.assertEqual(
                _records(tx[0]),
                [(int(RecordType.ALLOW_NEW_SOURCES), frozenset({_S1}))],
                msg="The retransmit must carry the same ALLOW_NEW_SOURCES record.",
            )

    def test__retransmit__exhausts_after_robustness_minus_one(self) -> None:
        """
        Ensure a Robustness Variable of 2 schedules exactly one retransmit
        (RV-1) — a second advance past the interval fires nothing more.

        Reference: RFC 3810 §9.1 (Robustness Variable — RV total transmissions).
        """

        with sysctl.override("mld.robustness", 2):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__icmp6__tx.random.randint",
                    return_value=200,
                )
            )
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))

            self.assertEqual(len(self._advance(ms=200)), 1, msg="The first (only) retransmit must fire.")
            self.assertEqual(len(self._advance(ms=200)), 0, msg="No further retransmit must fire after RV-1.")

    def test__compat_mode_change_cancels_retransmits(self) -> None:
        """
        Ensure switching into MLDv1 Host Compatibility Mode (an inbound
        MLDv1 Query) cancels the pending state-change retransmit train.

        Reference: RFC 3810 §8.2.1 (a compatibility-mode change cancels pending retransmissions).
        """

        with sysctl.override("mld.robustness", 3):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__icmp6__tx.random.randint",
                    return_value=200,
                )
            )
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))
            self.assertIn(
                _GROUP,
                self._packet_handler._icmp6_tx._mld_state_change__pending,
                msg="The join must leave a retransmit train pending.",
            )

            # An MLDv1 Query flips the interface to MLDv1 compat mode,
            # which must cancel the pending retransmit train (asserted on
            # the pending map directly, since the Query also schedules its
            # own current-state response frame).
            self._drive_rx(frame=_build_mld1_query_frame())

            self.assertEqual(
                self._packet_handler._icmp6_tx._mld_state_change__pending,
                {},
                msg="The compat-mode change must clear the pending retransmit train.",
            )

    def test__retransmit__fires_in_mldv1_mode(self) -> None:
        """
        Ensure a state-change whose retransmit train runs while the
        interface is in MLDv1 Host Compatibility Mode retransmits the
        coarse MLDv1 Report form (type 131), not an MLDv2 Report.

        Reference: RFC 3810 §8.3.1 (state-change retransmits take the MLDv1 form in v1 mode).
        """

        with sysctl.override("mld.version", 1), sysctl.override("mld.robustness", 2):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__icmp6__tx.random.randint",
                    return_value=200,
                )
            )
            before = len(self._frames_tx)
            self._socket.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, _ipv6_mreq(_GROUP))
            immediate = self._frames_tx[before:]
            self.assertEqual(len(immediate), 1, msg="The join must emit one immediate Report.")
            self.assertEqual(
                immediate[0][_OFFSET_ICMP6],
                int(Icmp6Type.MULTICAST_LISTENER_REPORT),
                msg="The immediate join Report must be an MLDv1 Report (type 131) in v1 mode.",
            )

            tx = self._advance(ms=200)
            self.assertEqual(len(tx), 1, msg="One robustness retransmit must fire.")
            self.assertEqual(
                tx[0][_OFFSET_ICMP6],
                int(Icmp6Type.MULTICAST_LISTENER_REPORT),
                msg="The retransmit must also take the MLDv1 Report form in v1 mode.",
            )

    def test__robustness_one__schedules_no_retransmit(self) -> None:
        """
        Ensure a Robustness Variable of 1 emits the state-change Report
        once and schedules no retransmit train (RV-1 = 0).

        Reference: RFC 3810 §9.1 (RV total transmissions — RV=1 means a single Report).
        """

        with sysctl.override("mld.robustness", 1):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__icmp6__tx.random.randint",
                    return_value=200,
                )
            )
            before = len(self._frames_tx)
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))

            self.assertEqual(len(self._frames_tx[before:]), 1, msg="RV=1 must emit exactly one Report.")
            self.assertEqual(
                self._packet_handler._icmp6_tx._mld_state_change__pending,
                {},
                msg="RV=1 must schedule no retransmit train.",
            )
            self.assertEqual(len(self._advance(ms=200)), 0, msg="No retransmit must fire when RV=1.")

    def test__retransmit__multiple_rounds_then_exhausts(self) -> None:
        """
        Ensure a Robustness Variable of 3 retransmits the state-change
        Report twice (RV-1 = 2) — the train decrements and re-arms across
        rounds before exhausting.

        Reference: RFC 3810 §6.1 (state-change Report retransmitted RV-1 times).
        """

        with sysctl.override("mld.robustness", 3):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__icmp6__tx.random.randint",
                    return_value=200,
                )
            )
            self._socket.setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, _group_source_req(_GROUP, _S1))

            self.assertEqual(len(self._advance(ms=200)), 1, msg="The first retransmit round must fire.")
            self.assertEqual(len(self._advance(ms=200)), 1, msg="The second retransmit round must fire.")
            self.assertEqual(len(self._advance(ms=200)), 0, msg="No third round fires after RV-1 = 2 rounds.")
