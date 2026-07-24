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
This module contains integration tests for the RFC 3376 §5.1 source-
bearing IGMPv3 state-change Reports — the ALLOW_NEW_SOURCES /
BLOCK_OLD_SOURCES / CHANGE_TO_*_MODE difference records emitted when a
socket source-filter option changes a group's merged interface filter,
and their robustness retransmission.

pytcp/tests/integration/protocols/igmp/test__igmp__source_state_change.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import override
from unittest.mock import patch

from net_addr import Ip4Address
from net_proto import IgmpV3RecordType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from pytcp import stack
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
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

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


def _mreq() -> bytes:
    """Pack an 8-byte ip_mreq (imr_multiaddr + INADDR_ANY interface)."""

    return bytes(_GROUP) + bytes(Ip4Address())


def _mreq_source(source: Ip4Address) -> bytes:
    """Pack a 12-byte ip_mreq_source (group + source + INADDR_ANY interface)."""

    return bytes(_GROUP) + bytes(source) + bytes(Ip4Address())


def _records(frame: bytes) -> list[tuple[IgmpV3RecordType, frozenset[Ip4Address]]]:
    """Decode the (type, source-set) of every record in an IGMPv3 Report frame."""

    ihl = (frame[14] & 0x0F) * 4
    igmp_bytes = frame[14 + ihl :]
    packet_rx = PacketRx(igmp_bytes)
    packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
    IgmpParser(packet_rx)
    message = packet_rx.igmp.message
    assert isinstance(message, IgmpMessageV3Report)

    return [(record.type, frozenset(record.source_addresses)) for record in message.records]


class TestIgmpSourceStateChange(IcmpTestCase):
    """
    The RFC 3376 §5.1 source-bearing IGMPv3 state-change Report tests.
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

    def _emitted_records(self, op: int, payload: bytes) -> list[tuple[IgmpV3RecordType, frozenset[Ip4Address]]]:
        """Apply a socket option and return the records of the single Report it emits."""

        before = len(self._frames_tx)
        self._socket.setsockopt(IPPROTO_IP, op, payload)
        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The state change must emit exactly one Report.")

        return _records(frames[0])

    def test__add_source__fresh_join_emits_allow_new_sources(self) -> None:
        """
        Ensure a first IP_ADD_SOURCE_MEMBERSHIP emits an ALLOW_NEW_SOURCES
        record for the added source — the non-member INCLUDE{} → INCLUDE{s}
        transition.

        Reference: RFC 3376 §5.1 (INCLUDE(A)→INCLUDE(B) sends ALLOW (B-A)).
        """

        self.assertEqual(
            self._emitted_records(IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1)),
            [(IgmpV3RecordType.ALLOW_NEW_SOURCES, frozenset({_S1}))],
            msg="A fresh source join must report ALLOW_NEW_SOURCES for the source.",
        )

    def test__add_source__second_source_emits_allow_for_delta_only(self) -> None:
        """
        Ensure a second IP_ADD_SOURCE_MEMBERSHIP emits an
        ALLOW_NEW_SOURCES record carrying only the newly added source.

        Reference: RFC 3376 §5.1 (the difference report carries only B-A).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        self.assertEqual(
            self._emitted_records(IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S2)),
            [(IgmpV3RecordType.ALLOW_NEW_SOURCES, frozenset({_S2}))],
            msg="Adding a second source must report ALLOW_NEW_SOURCES for only that source.",
        )

    def test__drop_source__emits_block_old_sources(self) -> None:
        """
        Ensure IP_DROP_SOURCE_MEMBERSHIP on one of several included
        sources emits a BLOCK_OLD_SOURCES record for the removed source.

        Reference: RFC 3376 §5.1 (INCLUDE(A)→INCLUDE(B) sends BLOCK (A-B)).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))
        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S2))

        self.assertEqual(
            self._emitted_records(IP_DROP_SOURCE_MEMBERSHIP, _mreq_source(_S1)),
            [(IgmpV3RecordType.BLOCK_OLD_SOURCES, frozenset({_S1}))],
            msg="Dropping an included source must report BLOCK_OLD_SOURCES for it.",
        )

    def test__block_source__emits_block_old_sources(self) -> None:
        """
        Ensure IP_BLOCK_SOURCE on an any-source (EXCLUDE{}) membership
        emits a BLOCK_OLD_SOURCES record for the newly blocked source.

        Reference: RFC 3376 §5.1 (EXCLUDE(A)→EXCLUDE(B) sends BLOCK (B-A)).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())

        self.assertEqual(
            self._emitted_records(IP_BLOCK_SOURCE, _mreq_source(_S1)),
            [(IgmpV3RecordType.BLOCK_OLD_SOURCES, frozenset({_S1}))],
            msg="Blocking a source must report BLOCK_OLD_SOURCES for it.",
        )

    def test__unblock_source__emits_allow_new_sources(self) -> None:
        """
        Ensure IP_UNBLOCK_SOURCE emits an ALLOW_NEW_SOURCES record for the
        source restored to reception.

        Reference: RFC 3376 §5.1 (EXCLUDE(A)→EXCLUDE(B) sends ALLOW (A-B)).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())
        self._socket.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, _mreq_source(_S1))

        self.assertEqual(
            self._emitted_records(IP_UNBLOCK_SOURCE, _mreq_source(_S1)),
            [(IgmpV3RecordType.ALLOW_NEW_SOURCES, frozenset({_S1}))],
            msg="Unblocking a source must report ALLOW_NEW_SOURCES for it.",
        )

    def test__mode_flip_to_exclude__emits_change_to_exclude_mode(self) -> None:
        """
        Ensure an interface filter that flips from INCLUDE to EXCLUDE
        (an any-source socket joining a group held only in INCLUDE mode)
        emits a CHANGE_TO_EXCLUDE_MODE record.

        Reference: RFC 3376 §5.1 (INCLUDE(A)→EXCLUDE(B) sends TO_EX (B)).
        Reference: RFC 3376 §3.2 (any EXCLUDE socket makes the interface EXCLUDE).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

        before = len(self._frames_tx)
        self._socket_b.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _mreq())
        frames = self._frames_tx[before:]

        self.assertEqual(len(frames), 1, msg="The mode flip must emit one Report.")
        self.assertEqual(
            _records(frames[0]),
            [(IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE, frozenset())],
            msg="An INCLUDE→EXCLUDE interface mode flip must report CHANGE_TO_EXCLUDE_MODE.",
        )

    def test__retransmit__carries_source_list(self) -> None:
        """
        Ensure the robustness retransmission of a source state-change
        Report carries the same source-bearing record as the immediate
        Report.

        Reference: RFC 3376 §5.1 (state-change Report retransmitted RV-1 times with its records).
        """

        with sysctl.override("igmp.robustness", 2):
            self.enterContext(
                patch(
                    "pytcp.runtime.packet_handler.packet_handler__igmp__tx.random.randint",
                    return_value=200,
                )
            )
            self._socket.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, _mreq_source(_S1))

            tx = self._advance(ms=200)
            self.assertEqual(len(tx), 1, msg="One robustness retransmit must fire at the chosen delay.")
            self.assertEqual(
                _records(tx[0]),
                [(IgmpV3RecordType.ALLOW_NEW_SOURCES, frozenset({_S1}))],
                msg="The retransmit must carry the same ALLOW_NEW_SOURCES record.",
            )
