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
This module contains integration tests for the RFC 3376 §5.2 source-
aware IGMPv3 Query responses — Current-State Records carrying the real
filter mode + source list, and the Group-and-Source-Specific Query
intersection math (IS_IN(A∩B) for an INCLUDE interface, IS_IN(B−A) for
an EXCLUDE interface, empty ⇒ no response).

pytcp/tests/integration/protocols/igmp/test__igmp__source_query_response.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import override

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import IgmpV3RecordType, IpProto
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.runtime.socket import (
    AF_INET,
    IP_ADD_MEMBERSHIP,
    IP_ADD_SOURCE_MEMBERSHIP,
    IP_BLOCK_SOURCE,
    IPPROTO_IP,
    SOCK_DGRAM,
    socket,
)
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip4Address("239.1.1.1")
_GROUP_MAC = MacAddress("01:00:5e:01:01:01")
_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_ALL_SYSTEMS_MAC = MacAddress("01:00:5e:00:00:01")
_ROUTER_IP = Ip4Address("10.0.1.1")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")
_S1 = Ip4Address("10.0.0.1")
_S2 = Ip4Address("10.0.0.2")
_S3 = Ip4Address("10.0.0.3")

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / igmp log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _query_frame(*, group: Ip4Address, sources: tuple[Ip4Address, ...] = ()) -> bytes:
    """
    Build an IGMPv3 Query. A 0.0.0.0 'group' is a General Query (to
    224.0.0.1); a non-zero 'group' with no 'sources' is a Group-Specific
    Query; with 'sources' it is a Group-and-Source-Specific Query.
    """

    body = (
        b"\x11"
        + bytes([100])
        + b"\x00\x00"
        + bytes(group)
        + b"\x02\x7d"
        + len(sources).to_bytes(2, "big")
        + b"".join(bytes(source) for source in sources)
    )
    cksum = inet_cksum(body)
    body = body[:2] + cksum.to_bytes(2, "big") + body[4:]

    general = group.is_unspecified
    ethernet = EthernetAssembler(
        ethernet__src=_ROUTER_MAC,
        ethernet__dst=_ALL_SYSTEMS_MAC if general else _GROUP_MAC,
        ethernet__payload=Ip4Assembler(
            ip4__src=_ROUTER_IP,
            ip4__dst=_ALL_SYSTEMS if general else group,
            ip4__ttl=1,
            ip4__payload=RawAssembler(raw__payload=body, ip_proto=IpProto.IGMP),
        ),
    )
    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buffer) for buffer in buffers)


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


class TestIgmpSourceQueryResponse(IcmpTestCase):
    """
    The RFC 3376 §5.2 source-aware IGMPv3 Query-response tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness, admit the group / all-systems MACs, and open a
        socket. Robustness is pinned to 1 so the join state-change Reports
        schedule no retransmit that would pollute the response windows.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.robustness", 1))
        self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)
        self._packet_handler._mac_multicast.append(_GROUP_MAC)
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(self._socket.close)
        # Force the response delay to 0 so the Query is answered inline.
        self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda max_resp_ms: 0
        )

    def _join_include(self, *sources: Ip4Address) -> None:
        """Join _GROUP in INCLUDE mode for the given sources."""

        for source in sources:
            self._socket.setsockopt(
                IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(source) + bytes(Ip4Address())
            )

    def _join_exclude(self, *blocked: Ip4Address) -> None:
        """Join _GROUP any-source (EXCLUDE{}) then block the given sources."""

        self._socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, bytes(_GROUP) + bytes(Ip4Address()))
        for source in blocked:
            self._socket.setsockopt(IPPROTO_IP, IP_BLOCK_SOURCE, bytes(_GROUP) + bytes(source) + bytes(Ip4Address()))

    def _query_records(self, **kwargs: object) -> list[tuple[IgmpV3RecordType, frozenset[Ip4Address]]]:
        """Drive a Query and return the records of the single Report it elicits."""

        before = len(self._frames_tx)
        self._drive_rx(frame=_query_frame(**kwargs))  # type: ignore[arg-type]
        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The Query must elicit exactly one Report.")

        return _records(frames[0])

    def test__general_query__current_state_carries_include_sources(self) -> None:
        """
        Ensure the General-Query response reports a group held in INCLUDE
        mode as a MODE_IS_INCLUDE Current-State Record carrying its source
        list.

        Reference: RFC 3376 §5.2 (General-Query response carries the real mode + source list).
        """

        self._join_include(_S1, _S2)

        self.assertEqual(
            self._query_records(group=Ip4Address()),
            [(IgmpV3RecordType.MODE_IS_INCLUDE, frozenset({_S1, _S2}))],
            msg="A General Query must report INCLUDE mode + the source list.",
        )

    def test__group_query__current_state_carries_exclude_sources(self) -> None:
        """
        Ensure the Group-Specific-Query response reports a group held in
        EXCLUDE mode as a MODE_IS_EXCLUDE record carrying its blocked
        source list.

        Reference: RFC 3376 §5.2 (group-timer expiry rule 2 reports the real filter).
        """

        self._join_exclude(_S1)

        self.assertEqual(
            self._query_records(group=_GROUP),
            [(IgmpV3RecordType.MODE_IS_EXCLUDE, frozenset({_S1}))],
            msg="A Group-Specific Query must report EXCLUDE mode + the blocked sources.",
        )

    def test__gssq__include_interface_answers_intersection(self) -> None:
        """
        Ensure a Group-and-Source-Specific Query on an INCLUDE(A)
        interface answers IS_IN(A∩B) for the queried sources B.

        Reference: RFC 3376 §5.2 (rule 3 table: INCLUDE(A) answers IS_IN (A*B)).
        """

        self._join_include(_S1, _S2)

        self.assertEqual(
            self._query_records(group=_GROUP, sources=(_S2, _S3)),
            [(IgmpV3RecordType.MODE_IS_INCLUDE, frozenset({_S2}))],
            msg="A GSSQ on INCLUDE(A) must answer IS_IN(A∩B).",
        )

    def test__gssq__exclude_interface_answers_difference(self) -> None:
        """
        Ensure a Group-and-Source-Specific Query on an EXCLUDE(A)
        interface answers IS_IN(B−A) for the queried sources B.

        Reference: RFC 3376 §5.2 (rule 3 table: EXCLUDE(A) answers IS_IN (B-A)).
        """

        self._join_exclude(_S1)

        self.assertEqual(
            self._query_records(group=_GROUP, sources=(_S1, _S2)),
            [(IgmpV3RecordType.MODE_IS_INCLUDE, frozenset({_S2}))],
            msg="A GSSQ on EXCLUDE(A) must answer IS_IN(B−A).",
        )

    def test__gssq__empty_result_sends_no_response(self) -> None:
        """
        Ensure a Group-and-Source-Specific Query whose computed source
        set is empty elicits no response.

        Reference: RFC 3376 §5.2 (an empty resulting source set sends no response).
        """

        self._join_include(_S1)

        before = len(self._frames_tx)
        self._drive_rx(frame=_query_frame(group=_GROUP, sources=(_S2,)))

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="A GSSQ with an empty IS_IN result must elicit no Report.",
        )
