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
This module contains integration tests for the IGMP graceful Leave a
host sends on shutdown (R7) — every joined IPv4 multicast group is
transitioned to INCLUDE{} in a single combined Report so routers prune
the memberships immediately instead of waiting for a query timeout.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__shutdown_leave.py

ver 3.0.10
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


def _igmp_report_frames(frames: list[bytes]) -> list[IgmpMessageV3Report]:
    """Decode every IGMPv3 Report carried in the given Ethernet frames."""

    reports: list[IgmpMessageV3Report] = []
    for frame in frames:
        if frame[12:14] != b"\x08\x00" or frame[14 + 9] != 2:
            continue
        ihl = (frame[14] & 0x0F) * 4
        igmp_bytes = frame[14 + ihl :]
        packet_rx = PacketRx(igmp_bytes)
        packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
        IgmpParser(packet_rx)
        message = packet_rx.igmp.message
        assert isinstance(message, IgmpMessageV3Report)
        reports.append(message)

    return reports


class TestIgmpShutdownLeave(NetworkTestCase):
    """
    The IGMP graceful-Leave-on-shutdown tests.
    """

    def test__igmp__shutdown_leave__reports_all_joined_groups(self) -> None:
        """
        Ensure the shutdown Leave emits a single combined Report
        transitioning every joined group to CHANGE_TO_INCLUDE_MODE, so a
        router prunes the host's memberships at once.

        Reference: RFC 3376 §5.1 (state-change Report transitions a group to INCLUDE on leave).
        """

        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))
        self._packet_handler._assign_ip4_multicast(Ip4Address("239.2.2.2"))

        before = len(self._frames_tx)
        self._packet_handler.send_igmp_leave_all()

        reports = _igmp_report_frames(self._frames_tx[before:])
        self.assertEqual(len(reports), 1, msg="The shutdown Leave is a single combined Report.")
        records = reports[0].records
        self.assertEqual(
            {record.multicast_address for record in records},
            {Ip4Address("239.1.1.1"), Ip4Address("239.2.2.2")},
            msg="The Leave must cover every joined group.",
        )
        self.assertTrue(
            all(record.type is IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE for record in records),
            msg="Every shutdown-Leave record must transition the group to INCLUDE{}.",
        )

    def test__igmp__shutdown_leave__excludes_all_systems_and_is_noop_when_empty(self) -> None:
        """
        Ensure the shutdown Leave never reports the permanent all-systems
        group 224.0.0.1 and emits nothing when no other group is joined.

        Reference: RFC 3376 §6 (the all-systems group is never reported).
        """

        before = len(self._frames_tx)
        self._packet_handler.send_igmp_leave_all()

        self.assertEqual(
            len(_igmp_report_frames(self._frames_tx[before:])),
            0,
            msg="With only the permanent all-systems group joined, the shutdown Leave emits nothing.",
        )
