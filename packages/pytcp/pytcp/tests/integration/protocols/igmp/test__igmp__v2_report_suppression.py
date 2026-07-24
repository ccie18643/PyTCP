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
This module contains integration tests for the RFC 2236 §3 IGMPv1/v2
report suppression — in older-version compatibility mode, hearing
another host's Membership Report for a group cancels this host's own
pending Query response for that group.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__v2_report_suppression.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import IpProto
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip4Address("239.1.1.1")
_GROUP_MAC = MacAddress("01:00:5e:01:01:01")
_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_ALL_SYSTEMS_MAC = MacAddress("01:00:5e:00:00:01")
_ROUTER_IP = Ip4Address("10.0.1.1")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")
_OTHER_HOST_IP = Ip4Address("10.0.1.50")
_OTHER_HOST_MAC = MacAddress("02:00:00:00:00:50")


def _frame(*, body: bytes, src_mac: MacAddress, dst_mac: MacAddress, src_ip: Ip4Address, dst_ip: Ip4Address) -> bytes:
    """Wrap an 8-octet IGMP body in Ethernet/IPv4 with TTL=1."""

    ethernet = EthernetAssembler(
        ethernet__src=src_mac,
        ethernet__dst=dst_mac,
        ethernet__payload=Ip4Assembler(
            ip4__src=src_ip,
            ip4__dst=dst_ip,
            ip4__ttl=1,
            ip4__payload=RawAssembler(raw__payload=body, ip_proto=IpProto.IGMP),
        ),
    )
    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buf) for buf in buffers)


def _igmp_body(*, type_: int, max_resp_code: int, group: Ip4Address) -> bytes:
    """Build an 8-octet IGMP message body (type, max-resp, cksum, group)."""

    body = bytes([type_, max_resp_code]) + b"\x00\x00" + bytes(group)
    cksum = inet_cksum(body)

    return body[:2] + cksum.to_bytes(2, "big") + body[4:]


def _v2_query_frame() -> bytes:
    """An IGMPv2 General Query (8 octets, non-zero Max Resp Code) to 224.0.0.1."""

    return _frame(
        body=_igmp_body(type_=0x11, max_resp_code=100, group=Ip4Address()),
        src_mac=_ROUTER_MAC,
        dst_mac=_ALL_SYSTEMS_MAC,
        src_ip=_ROUTER_IP,
        dst_ip=_ALL_SYSTEMS,
    )


def _v2_report_frame(group: Ip4Address) -> bytes:
    """An IGMPv2 Membership Report (type 0x16) for 'group' from another host."""

    return _frame(
        body=_igmp_body(type_=0x16, max_resp_code=0, group=group),
        src_mac=_OTHER_HOST_MAC,
        dst_mac=_GROUP_MAC,
        src_ip=_OTHER_HOST_IP,
        dst_ip=group,
    )


class TestIgmpV2ReportSuppression(IcmpTestCase):
    """
    The RFC 2236 §3 IGMPv1/v2 report-suppression tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness pinned to IGMPv2 compatibility mode with
        Robustness 1 (no state-change retransmits to confound the
        response window), admit the all-systems / group MACs, and join
        the group under test.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.version", 2))
        self.enterContext(sysctl.override("igmp.robustness", 1))
        self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)
        self._packet_handler._mac_multicast.append(_GROUP_MAC)
        self._packet_handler._assign_ip4_multicast(_GROUP)
        self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda max_resp_ms: 500
        )

    def test__igmp__v2__report_from_another_host_suppresses_pending_response(self) -> None:
        """
        Ensure that, with a Query response pending in IGMPv2 mode,
        another host's IGMPv2 Membership Report for the group suppresses
        this host's own pending Report so none is sent when the timer
        fires.

        Reference: RFC 2236 §3 (IGMPv2 report suppression).
        """

        self._drive_rx(frame=_v2_query_frame())
        self._drive_rx(frame=_v2_report_frame(_GROUP))

        self.assertEqual(
            self._packet_handler._packet_stats_rx.igmp__membership_query__suppressed,
            1,
            msg="Another host's v2 Report must suppress the pending Report for the group.",
        )
        self.assertEqual(
            len(self._advance(ms=500)),
            0,
            msg="The suppressed Report must not be sent when the response timer fires.",
        )

    def test__igmp__v2__unsuppressed_response_is_sent(self) -> None:
        """
        Ensure that, absent another host's Report, the pending IGMPv2
        Query response is sent for the group when the timer fires.

        Reference: RFC 2236 §3 (a host that hears no other Report sends its own).
        """

        self._drive_rx(frame=_v2_query_frame())

        self.assertEqual(
            self._packet_handler._packet_stats_rx.igmp__membership_query__suppressed,
            0,
            msg="With no other host's Report, nothing is suppressed.",
        )
        self.assertEqual(
            len(self._advance(ms=500)),
            1,
            msg="The unsuppressed v2 Report must be sent when the response timer fires.",
        )
