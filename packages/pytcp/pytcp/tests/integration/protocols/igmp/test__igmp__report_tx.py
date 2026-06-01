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
This module contains integration tests for the IGMPv3 Membership
Report TX path.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__report_tx.py

ver 3.0.8
"""

from types import SimpleNamespace

from net_addr import Ip4Address, MacAddress
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3RecordType,
)
from pytcp import stack
from pytcp.tests.lib.network_testcase import NetworkTestCase

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / igmp log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _parse_igmp_from_ethernet(frame: bytes) -> IgmpMessageV3Report:
    """Decode the IGMP message carried in an Ethernet/IPv4 frame."""

    ihl = (frame[14] & 0x0F) * 4
    igmp_bytes = frame[14 + ihl :]

    packet_rx = PacketRx(igmp_bytes)
    packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
    IgmpParser(packet_rx)

    message = packet_rx.igmp.message
    assert isinstance(message, IgmpMessageV3Report)

    return message


class TestIgmpReportTx(NetworkTestCase):
    """
    The IGMPv3 Membership Report TX-path tests.
    """

    def test__igmp__report_tx__framing(self) -> None:
        """
        Ensure an emitted IGMPv3 Report is sent to 224.0.0.22 (its
        multicast MAC) with TTL=1 and the IPv4 Protocol field set to
        IGMP (2).

        Reference: RFC 3376 §4 (Report sent with Router Alert + TTL 1).
        Reference: RFC 3376 §4.2.14 (Reports sent to 224.0.0.22).
        Reference: RFC 1112 §6.4 (IPv4-to-Ethernet multicast MAC mapping).
        """

        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

        before = len(self._frames_tx)
        self._packet_handler._send_igmp_v3_report()
        tx = self._frames_tx[before:]

        self.assertEqual(len(tx), 1, msg="A single IGMPv3 Report frame must be emitted.")
        frame = tx[0]

        self.assertEqual(
            MacAddress(frame[0:6]),
            MacAddress("01:00:5e:00:00:16"),
            msg="The Report's Ethernet destination must be the 224.0.0.22 multicast MAC.",
        )

        ihl = (frame[14] & 0x0F) * 4
        self.assertEqual(frame[14 + 8], 1, msg="The Report's IPv4 TTL must be 1.")
        self.assertEqual(frame[14 + 9], 2, msg="The Report's IPv4 Protocol must be IGMP (2).")
        self.assertEqual(
            Ip4Address(frame[14 + 16 : 14 + 20]),
            Ip4Address("224.0.0.22"),
            msg="The Report's IPv4 destination must be 224.0.0.22.",
        )
        self.assertEqual(frame[14 + ihl], 0x22, msg="The IGMP message type must be V3 Report (0x22).")

    def test__igmp__report_tx__records_joined_groups_excluding_all_systems(self) -> None:
        """
        Ensure the emitted Report carries a MODE_IS_EXCLUDE record for
        each joined group but omits the all-systems group 224.0.0.1.

        Reference: RFC 3376 §4.2.12 (MODE_IS_EXCLUDE current-state record).
        Reference: RFC 3376 §6 (all-systems group is never reported).
        """

        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

        before = len(self._frames_tx)
        self._packet_handler._send_igmp_v3_report()
        report = _parse_igmp_from_ethernet(self._frames_tx[before:][0])

        reported_groups = {record.multicast_address for record in report.records}

        self.assertIn(Ip4Address("239.1.1.1"), reported_groups)
        self.assertNotIn(
            Ip4Address("224.0.0.1"),
            reported_groups,
            msg="The all-systems group 224.0.0.1 must never be reported.",
        )
        for record in report.records:
            self.assertEqual(
                record.type,
                IgmpV3RecordType.MODE_IS_EXCLUDE,
                msg="A current-state Report uses MODE_IS_EXCLUDE records.",
            )

    def test__igmp__report_tx__counter(self) -> None:
        """
        Ensure emitting a Report bumps the igmp__v3_report__send TX
        counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

        before = self._packet_handler.packet_stats_tx.igmp__v3_report__send
        self._packet_handler._send_igmp_v3_report()

        self.assertEqual(
            self._packet_handler.packet_stats_tx.igmp__v3_report__send,
            before + 1,
            msg="Emitting an IGMPv3 Report must bump igmp__v3_report__send.",
        )

    def test__igmp__report_tx__no_groups_no_emit(self) -> None:
        """
        Ensure that with only the all-systems group joined (no reportable
        groups) no Report frame is emitted.

        Reference: RFC 3376 §6 (all-systems group is never reported).
        """

        # The harness preseeds only the all-systems group 224.0.0.1 as
        # the sole reception filter; no other group is joined here.
        before = len(self._frames_tx)
        self._packet_handler._send_igmp_v3_report()

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="No Report must be emitted when only the all-systems group is joined.",
        )
