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
This module contains integration tests for the RFC 3376 §7 Host
Compatibility Mode state machine — an IGMPv3 host falling back to
IGMPv1 / IGMPv2 behaviour in the presence of an older-version querier.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__version_fallback.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import IgmpVersion, IpProto
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.protocols.igmp import igmp__constants
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_ALL_SYSTEMS_MAC = MacAddress("01:00:5e:00:00:01")
_ROUTER_IP = Ip4Address("10.0.1.1")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")


def _general_query_frame(*, max_resp_code: int, v3: bool = False) -> bytes:
    """
    Build a General Query frame to 224.0.0.1. An 8-octet body is a
    v1 Query (max_resp_code 0) or v2 Query (non-zero); the 12-octet
    body (v3=True) carries the QRV/QQIC/source-count fixed tail.
    """

    body = b"\x11" + bytes([max_resp_code]) + b"\x00\x00" + b"\x00\x00\x00\x00"
    if v3:
        body += b"\x02\x7d\x00\x00"  # Resv|S|QRV=2, QQIC=125, sources=0
    cksum = inet_cksum(body)
    body = body[:2] + cksum.to_bytes(2, "big") + body[4:]

    ethernet = EthernetAssembler(
        ethernet__src=_ROUTER_MAC,
        ethernet__dst=_ALL_SYSTEMS_MAC,
        ethernet__payload=Ip4Assembler(
            ip4__src=_ROUTER_IP,
            ip4__dst=_ALL_SYSTEMS,
            ip4__ttl=1,
            ip4__payload=RawAssembler(raw__payload=body, ip_proto=IpProto.IGMP),
        ),
    )
    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buf) for buf in buffers)


class TestIgmpVersionFallback(IcmpTestCase):
    """
    The RFC 3376 §7 Host Compatibility Mode state-machine tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and admit the all-systems multicast MAC so the
        Ethernet RX accepts a Query addressed to 224.0.0.1.
        """

        super().setUp()
        self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)

    def test__igmp__mode__defaults_to_v3(self) -> None:
        """
        Ensure a freshly initialised interface with no older-version
        querier seen reports Host Compatibility Mode IGMPv3.

        Reference: RFC 3376 §7.2.1 (default mode is IGMPv3).
        """

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V3)

    def test__igmp__mode__v2_query_flips_to_v2(self) -> None:
        """
        Ensure receiving an IGMPv2 General Query (8 octets, non-zero Max
        Resp Code) switches the interface to Host Compatibility Mode
        IGMPv2.

        Reference: RFC 3376 §7.2.1 (IGMPv2 Querier Present → IGMPv2 mode).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=100))

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

    def test__igmp__mode__v1_query_flips_to_v1(self) -> None:
        """
        Ensure receiving an IGMPv1 General Query (8 octets, zero Max Resp
        Code) switches the interface to Host Compatibility Mode IGMPv1.

        Reference: RFC 3376 §7.2.1 (IGMPv1 Querier Present → IGMPv1 mode).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=0))

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V1)

    def test__igmp__mode__reverts_to_v3_after_timeout(self) -> None:
        """
        Ensure the interface reverts to Host Compatibility Mode IGMPv3
        once the Older Version Querier Present timeout elapses with no
        further older-version Query.

        Reference: RFC 3376 §8.12 (Older Version Querier Present Timeout).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=100))
        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

        # Timeout = RV * Query Interval + one Query Response Interval;
        # advance just past it.
        timeout_ms = igmp__constants.IGMP__ROBUSTNESS_VARIABLE * igmp__constants.IGMP__QUERY_INTERVAL__MS + 100 * 100
        self._advance(ms=timeout_ms + 1)

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V3)

    def test__igmp__mode__v3_query_does_not_lower_mode(self) -> None:
        """
        Ensure an IGMPv3 General Query never lowers the compatibility
        mode — a host already in IGMPv2 mode stays in IGMPv2.

        Reference: RFC 3376 §7.2.1 (mode lowers only on an older-version Query).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=100))
        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

        self._drive_rx(frame=_general_query_frame(max_resp_code=100, v3=True))

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

    def test__igmp__mode__forced_version_pins_mode(self) -> None:
        """
        Ensure a forced 'igmp.version' sysctl pins the compatibility mode
        regardless of the queriers heard.

        Reference: RFC 3376 §7.2.1 (administrative version override).
        """

        with sysctl.override("igmp.version", 2):
            self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)
        with sysctl.override("igmp.version", 1):
            self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V1)

    def test__igmp__mode__change_cancels_pending_state_change_retransmit(self) -> None:
        """
        Ensure a compatibility-mode change cancels the pending
        state-change retransmit train so a stale v3 retransmit cannot
        fire after the host has dropped to an older mode.

        Reference: RFC 3376 §7.2.1 (a mode change cancels all pending response and retransmission timers).
        """

        # Pin the v2 Query's response delay well outside the advance
        # window below so only the (cancelled) state-change retransmit
        # could fire during it — the query response itself is a separate
        # timer that must not confound this assertion.
        self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda max_resp_ms: 9000
        )

        # Join a group → immediate v3 Report + a pending robustness
        # retransmit (default RV=2 schedules one).
        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))
        self.assertNotEqual(
            self._packet_handler._igmp_tx._igmp_state_change__pending,
            {},
            msg="The join must leave a pending state-change retransmit.",
        )

        # A v2 Query flips the mode → the pending retransmit is cancelled.
        self._drive_rx(frame=_general_query_frame(max_resp_code=100))

        self.assertEqual(
            self._packet_handler._igmp_tx._igmp_state_change__pending,
            {},
            msg="A mode change must clear the pending state-change retransmits.",
        )
        # The cancelled retransmit must never fire afterwards.
        self.assertEqual(
            len(self._advance(ms=igmp__constants.IGMP__UNSOLICITED_REPORT_INTERVAL__MS + 1)),
            0,
            msg="The cancelled state-change retransmit must not fire after a mode change.",
        )


def _igmp_tx_summary(frame: bytes) -> tuple[int, Ip4Address]:
    """Return the (IGMP type byte, IPv4 destination) of an emitted IGMP frame."""

    ihl = (frame[14] & 0x0F) * 4
    return frame[14 + ihl], Ip4Address(frame[30:34])


class TestIgmpVersionFallbackReportForm(IcmpTestCase):
    """
    The RFC 3376 §7 report-form selection (query-response + state-change) tests.
    """

    _GROUP = Ip4Address("239.1.1.1")

    def test__igmp__v2_mode__join_emits_v2_report_to_group(self) -> None:
        """
        Ensure joining a group in IGMPv2 compatibility mode emits an
        IGMPv2 Membership Report (type 0x16) to the group address rather
        than a v3 Report to 224.0.0.22.

        Reference: RFC 2236 §3 (IGMPv2 host sends a Membership Report to the group).
        """

        with sysctl.override("igmp.version", 2):
            before = len(self._frames_tx)
            self._packet_handler._assign_ip4_multicast(self._GROUP)

        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The v2-mode join emits one Report.")
        igmp_type, ip4_dst = _igmp_tx_summary(frames[0])
        self.assertEqual(igmp_type, 0x16, msg="The v2-mode join must be an IGMPv2 Membership Report (0x16).")
        self.assertEqual(ip4_dst, self._GROUP, msg="The v2 Report must be sent to the group address.")

    def test__igmp__v2_mode__leave_emits_v2_leave_to_all_routers(self) -> None:
        """
        Ensure leaving a group in IGMPv2 compatibility mode emits an
        IGMPv2 Leave Group (type 0x17) to the all-routers group
        224.0.0.2.

        Reference: RFC 2236 §3 (IGMPv2 Leave Group sent to 224.0.0.2).
        """

        with sysctl.override("igmp.version", 2):
            self._packet_handler._assign_ip4_multicast(self._GROUP)
            before = len(self._frames_tx)
            self._packet_handler._remove_ip4_multicast(self._GROUP)

        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The v2-mode leave emits one Leave Group.")
        igmp_type, ip4_dst = _igmp_tx_summary(frames[0])
        self.assertEqual(igmp_type, 0x17, msg="The v2-mode leave must be an IGMPv2 Leave Group (0x17).")
        self.assertEqual(ip4_dst, Ip4Address("224.0.0.2"), msg="The v2 Leave must go to the all-routers group.")

    def test__igmp__v1_mode__join_emits_v1_report_to_group(self) -> None:
        """
        Ensure joining a group in IGMPv1 compatibility mode emits an
        IGMPv1 Membership Report (type 0x12) to the group address.

        Reference: RFC 1112 §6 (IGMPv1 host Membership Report).
        """

        with sysctl.override("igmp.version", 1):
            before = len(self._frames_tx)
            self._packet_handler._assign_ip4_multicast(self._GROUP)

        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The v1-mode join emits one Report.")
        igmp_type, ip4_dst = _igmp_tx_summary(frames[0])
        self.assertEqual(igmp_type, 0x12, msg="The v1-mode join must be an IGMPv1 Membership Report (0x12).")
        self.assertEqual(ip4_dst, self._GROUP, msg="The v1 Report must be sent to the group address.")

    def test__igmp__v1_mode__leave_emits_nothing(self) -> None:
        """
        Ensure leaving a group in IGMPv1 compatibility mode emits no
        packet — IGMPv1 has no Leave message.

        Reference: RFC 1112 §6 (IGMPv1 has no Leave Group message).
        """

        with sysctl.override("igmp.version", 1):
            self._packet_handler._assign_ip4_multicast(self._GROUP)
            before = len(self._frames_tx)
            self._packet_handler._remove_ip4_multicast(self._GROUP)

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="An IGMPv1-mode leave must emit nothing (no v1 Leave message exists).",
        )

    def test__igmp__v2_mode__query_response_is_per_group_v2_report(self) -> None:
        """
        Ensure a Query in IGMPv2 compatibility mode is answered with an
        IGMPv2 Membership Report per joined group, sent to each group
        address.

        Reference: RFC 2236 §3 (IGMPv2 Query response is a per-group Report).
        """

        with sysctl.override("igmp.version", 2):
            self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)
            self._packet_handler._assign_ip4_multicast(self._GROUP)
            self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
                lambda max_resp_ms: 0
            )
            before = len(self._frames_tx)
            self._drive_rx(frame=_general_query_frame(max_resp_code=100))

        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="The v2 query response is one per-group Report.")
        igmp_type, ip4_dst = _igmp_tx_summary(frames[0])
        self.assertEqual(igmp_type, 0x16, msg="The v2 query response must be an IGMPv2 Membership Report (0x16).")
        self.assertEqual(ip4_dst, self._GROUP, msg="The v2 query-response Report must go to the group address.")
