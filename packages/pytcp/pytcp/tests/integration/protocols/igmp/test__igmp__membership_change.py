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
This module contains integration tests for the IGMP membership-change
report (the unsolicited state-change Report on join / leave).

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__membership_change.py

ver 3.0.8
"""

from types import SimpleNamespace

from net_addr import Ip4Address
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3RecordType,
)
from pytcp.tests.lib.network_testcase import NetworkTestCase


def _parse_report(frame: bytes) -> IgmpMessageV3Report:
    """Decode the IGMPv3 Report carried in an Ethernet/IPv4 frame."""

    ihl = (frame[14] & 0x0F) * 4
    igmp_bytes = frame[14 + ihl :]

    packet_rx = PacketRx(igmp_bytes)
    packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
    IgmpParser(packet_rx)

    message = packet_rx.igmp.message
    assert isinstance(message, IgmpMessageV3Report)

    return message


class TestIgmpMembershipChange(NetworkTestCase):
    """
    The IGMP membership-change (join / leave) state-change Report tests.
    """

    def test__igmp__join_emits_change_to_exclude_report(self) -> None:
        """
        Ensure joining a group emits an unsolicited state-change Report
        carrying a single CHANGE_TO_EXCLUDE_MODE record for that group.

        Reference: RFC 3376 §5.1 (state-change Report on join).
        Reference: RFC 3376 §4.2.12 (CHANGE_TO_EXCLUDE_MODE record).
        """

        before = len(self._frames_tx)
        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))
        tx = self._frames_tx[before:]

        self.assertEqual(len(tx), 1, msg="A join must emit exactly one state-change Report.")
        report = _parse_report(tx[0])

        self.assertEqual(len(report.records), 1, msg="The state-change Report carries one group record.")
        self.assertEqual(report.records[0].multicast_address, Ip4Address("239.1.1.1"))
        self.assertEqual(report.records[0].type, IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE)

    def test__igmp__leave_emits_change_to_include_report(self) -> None:
        """
        Ensure leaving a group emits a state-change Report carrying a
        single CHANGE_TO_INCLUDE_MODE record (empty source list) for
        that group.

        Reference: RFC 3376 §5.1 (state-change Report on leave).
        Reference: RFC 3376 §4.2.12 (CHANGE_TO_INCLUDE_MODE record).
        """

        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

        before = len(self._frames_tx)
        self._packet_handler._remove_ip4_multicast(Ip4Address("239.1.1.1"))
        tx = self._frames_tx[before:]

        self.assertEqual(len(tx), 1, msg="A leave must emit exactly one state-change Report.")
        report = _parse_report(tx[0])

        self.assertEqual(len(report.records), 1, msg="The state-change Report carries one group record.")
        self.assertEqual(report.records[0].multicast_address, Ip4Address("239.1.1.1"))
        self.assertEqual(report.records[0].type, IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE)

    def test__igmp__all_systems_group_change_emits_nothing(self) -> None:
        """
        Ensure joining (or leaving) the all-systems group 224.0.0.1
        emits no Report — it is never reported.

        Reference: RFC 3376 §6 (all-systems group never reported).
        """

        before = len(self._frames_tx)
        self._packet_handler._assign_ip4_multicast(Ip4Address("224.0.0.1"))
        self._packet_handler._remove_ip4_multicast(Ip4Address("224.0.0.1"))

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="The all-systems group must never trigger a state-change Report.",
        )
