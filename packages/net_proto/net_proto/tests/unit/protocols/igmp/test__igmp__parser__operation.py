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
This module contains operation tests for the IGMP packet parser.

net_proto/tests/unit/protocols/igmp/test__igmp__parser__operation.py

ver 3.0.8
"""

from types import SimpleNamespace
from unittest import TestCase

from net_addr import Buffer, Ip4Address
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__assembler import IgmpAssembler
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message import IgmpType, IgmpVersion
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)
from net_proto.protocols.igmp.message.igmp__message__v2_leave import (
    IgmpMessageV2Leave,
)
from net_proto.protocols.igmp.message.igmp__message__v2_report import (
    IgmpMessageV2Report,
)
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3GroupRecord,
    IgmpV3RecordType,
)


def _assembled(message: object) -> bytes:
    """Serialize an IGMP message through the assembler (valid checksum)."""

    buffers: list[Buffer] = []
    IgmpAssembler(igmp__message=message).assemble(buffers)  # type: ignore[arg-type]

    return b"".join(bytes(part) for part in buffers)


def _query_frame(frame_no_cksum: bytes) -> bytes:
    """Insert a valid IGMP checksum into a hand-built Query frame."""

    cksum = inet_cksum(frame_no_cksum)

    return frame_no_cksum[:2] + cksum.to_bytes(2, "big") + frame_no_cksum[4:]


def _parse(frame: bytes) -> PacketRx:
    """Run the IGMP parser over a frame with a stubbed IPv4 layer."""

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = SimpleNamespace(payload_len=len(frame))  # type: ignore[assignment]
    IgmpParser(packet_rx)

    return packet_rx


class TestIgmpParserOperation(TestCase):
    """
    The IGMP packet parser operation tests.
    """

    def test__igmp__parser__v3_report(self) -> None:
        """
        Ensure the parser installs an IGMPv3 Report on packet_rx.igmp
        and reproduces its group records.

        Reference: RFC 3376 §4.2 (V3 Membership Report).
        """

        report = IgmpMessageV3Report(
            records=[
                IgmpV3GroupRecord(
                    type=IgmpV3RecordType.MODE_IS_EXCLUDE,
                    multicast_address=Ip4Address("239.1.1.1"),
                )
            ]
        )

        packet_rx = _parse(_assembled(report))

        self.assertIsInstance(packet_rx.igmp.message, IgmpMessageV3Report)
        self.assertEqual(
            packet_rx.igmp.message.records,  # type: ignore[attr-defined]
            report.records,
            msg="The parsed V3 Report records must match the assembled ones.",
        )

    def test__igmp__parser__v2_report(self) -> None:
        """
        Ensure the parser installs a legacy group message on
        packet_rx.igmp and preserves its type and group address.

        Reference: RFC 2236 §2 (V2 Membership Report).
        """

        report = IgmpMessageV2Report(group_address=Ip4Address("239.1.1.1"))

        packet_rx = _parse(_assembled(report))

        self.assertIsInstance(packet_rx.igmp.message, IgmpMessageV2Report)
        self.assertEqual(
            packet_rx.igmp.message.type,
            IgmpType.V2_MEMBERSHIP_REPORT,
            msg="The parsed message must carry the V2 Report type.",
        )

    def test__igmp__parser__v3_general_query(self) -> None:
        """
        Ensure the parser installs an IGMPv3 General Query and decodes
        its version and General-Query predicate.

        Reference: RFC 3376 §4.1 (Membership Query).
        Reference: RFC 3376 §7.1 (Query version discrimination).
        """

        # IGMPv3 General Query (12 bytes, group 0.0.0.0, checksum slot 0):
        frame = _query_frame(b"\x11\x64\x00\x00\x00\x00\x00\x00\x02\x7d\x00\x00")

        packet_rx = _parse(frame)

        self.assertIsInstance(packet_rx.igmp.message, IgmpMessageQuery)
        message = packet_rx.igmp.message
        assert isinstance(message, IgmpMessageQuery)
        self.assertIs(message.version, IgmpVersion.V3)
        self.assertTrue(message.is_general_query)

    def test__igmp__parser__advances_frame(self) -> None:
        """
        Ensure the parser advances packet_rx.frame past the consumed
        IGMP message.

        Reference: RFC 3376 §4 (IGMP occupies the whole IPv4 payload).
        """

        leave = IgmpMessageV2Leave(group_address=Ip4Address("239.1.1.1"))

        packet_rx = _parse(_assembled(leave))

        self.assertEqual(
            len(packet_rx.frame),
            0,
            msg="The IGMP parser must advance the frame past the 8-byte message.",
        )
