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
This module contains integration tests for the IGMP Membership Query
RX path (the host Query-response state machine).

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__query_response.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import EthernetAssembler, Ip4Assembler, IpProto, RawAssembler
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# The all-systems group 224.0.0.1 and its Ethernet multicast MAC, the
# IP destination of an IGMP General Query (RFC 3376 §4.1.12).
_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_ALL_SYSTEMS_MAC = MacAddress("01:00:5e:00:00:01")
_ROUTER_IP = Ip4Address("10.0.1.1")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")


def _igmp_general_query_bytes(*, max_resp_code: int, bad_cksum: bool = False) -> bytes:
    """Build a 12-byte IGMPv3 General Query with a valid (or broken) checksum."""

    body = (
        b"\x11"  # Type = Membership Query
        + bytes([max_resp_code])  # Max Resp Code
        + b"\x00\x00"  # Checksum (zero for the compute)
        + b"\x00\x00\x00\x00"  # Group Address = 0.0.0.0 (General)
        + b"\x02"  # Resv | S | QRV = 0/0/2
        + b"\x7d"  # QQIC = 125
        + b"\x00\x00"  # Number of Sources = 0
    )
    cksum = 0xFFFF if bad_cksum else inet_cksum(body)

    return body[:2] + cksum.to_bytes(2, "big") + body[4:]


def _query_frame(*, max_resp_code: int, bad_cksum: bool = False, ttl: int = 1) -> bytes:
    """Wrap an IGMP General Query in Ethernet/IPv4 destined to 224.0.0.1."""

    ethernet = EthernetAssembler(
        ethernet__src=_ROUTER_MAC,
        ethernet__dst=_ALL_SYSTEMS_MAC,
        ethernet__payload=Ip4Assembler(
            ip4__src=_ROUTER_IP,
            ip4__dst=_ALL_SYSTEMS,
            ip4__ttl=ttl,
            ip4__payload=RawAssembler(
                raw__payload=_igmp_general_query_bytes(max_resp_code=max_resp_code, bad_cksum=bad_cksum),
                ip_proto=IpProto.IGMP,
            ),
        ),
    )

    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buf) for buf in buffers)


class TestIgmpQueryResponse(IcmpTestCase):
    """
    The IGMP Membership Query RX / response-scheduling tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and admit the all-systems multicast MAC so the
        Ethernet RX accepts a Query addressed to 224.0.0.1, then join a
        reportable group.
        """

        super().setUp()
        # Pin Robustness to 1 so the setUp join does not schedule a
        # state-change retransmit that would land in the query-response
        # timer windows these tests advance through.
        self.enterContext(sysctl.override("igmp.robustness", 1))
        self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)
        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

    def _patch_delay(self, *, returns_ms: int) -> None:
        """Force the query delay picker to a deterministic value."""

        self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda max_resp_ms: returns_ms
        )

    def test__igmp__query__zero_delay_responds_immediately(self) -> None:
        """
        Ensure a Query whose picked response delay is 0 elicits an
        immediate IGMPv3 Report.

        Reference: RFC 3376 §5.2 (host Query-response).
        """

        self._patch_delay(returns_ms=0)

        tx = self._drive_rx(frame=_query_frame(max_resp_code=100))

        self.assertEqual(len(tx), 1, msg="A zero-delay Query must elicit one immediate Report.")
        self.assertEqual(self._packet_handler._packet_stats_rx.igmp__membership_query, 1)
        self.assertEqual(self._packet_handler._packet_stats_rx.igmp__membership_query__respond, 1)

    def test__igmp__query__nonzero_delay_defers_report(self) -> None:
        """
        Ensure a Query with a non-zero picked delay schedules the Report
        rather than emitting it synchronously; it fires once the delay
        elapses.

        Reference: RFC 3376 §5.2 (random-delay response window).
        """

        self._patch_delay(returns_ms=500)

        tx = self._drive_rx(frame=_query_frame(max_resp_code=100))

        self.assertEqual(len(tx), 0, msg="A 500 ms-delayed Query must not emit synchronously.")
        self.assertEqual(self._packet_handler._packet_stats_rx.igmp__membership_query__scheduled, 1)

        self.assertEqual(len(self._advance(ms=499)), 0, msg="No Report before the delay elapses.")

        tx_fire = self._advance(ms=1)
        self.assertEqual(len(tx_fire), 1, msg="The Report fires when the delay elapses.")
        self.assertEqual(self._packet_handler._packet_stats_rx.igmp__membership_query__respond, 1)

    def test__igmp__query__bad_checksum_dropped(self) -> None:
        """
        Ensure a Query with an invalid IGMP checksum is dropped without
        a response.

        Reference: RFC 3376 §4.1.2 (checksum MUST be verified).
        """

        tx = self._drive_rx(frame=_query_frame(max_resp_code=100, bad_cksum=True))

        self.assertEqual(len(tx), 0, msg="A bad-checksum Query must elicit no Report.")
        self.assertEqual(self._packet_handler._packet_stats_rx.igmp__failed_parse__drop, 1)

    def test__igmp__rx__ttl_not_one_dropped(self) -> None:
        """
        Ensure an inbound IGMP message with an IP TTL other than 1 is
        dropped before processing and elicits no response, matching the
        Linux martian-IGMP guard.

        Reference: RFC 3376 §4 (IGMP messages are sent with an IP TTL of 1).
        """

        tx = self._drive_rx(frame=_query_frame(max_resp_code=100, ttl=64))

        self.assertEqual(len(tx), 0, msg="A TTL != 1 Query must elicit no Report.")
        self.assertEqual(
            self._packet_handler._packet_stats_rx.igmp__ttl_invalid__drop,
            1,
            msg="A TTL != 1 IGMP message must bump the TTL-invalid drop counter.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.igmp__membership_query,
            0,
            msg="A dropped TTL != 1 Query must not reach Query processing.",
        )
