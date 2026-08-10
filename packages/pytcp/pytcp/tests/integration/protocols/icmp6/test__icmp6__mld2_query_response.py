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
Integration test for the MLDv2 §5.1.10 listener-side
Query → Report response. An inbound MLDv2 General Query
(type 130) drives a listener-side Report (type 143) on
the wire.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_query_response.py

ver 3.0.10
"""

from typing import override

from net_addr import MacAddress
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


def _build_mldv2_general_query_frame() -> bytes:
    """
    Hand-construct an MLDv2 General Query frame:
    Ethernet/IPv6/ICMPv6 type=130 with the canonical
    Query-payload shape from RFC 3810 §5.1.

    - src=fe80::1 (router link-local)
    - dst=ff02::1 (all-nodes; standard General-Query destination)
    - hop=1
    - MLDv2 Query: MRC=10000ms, multicast_address=:: (General),
      QRV=2, QQIC=125, N=0 (no source list).

    PyTCP's Phase-1 Query handler does not decode the Query
    payload fields; the listener responds immediately to any
    well-formed inbound Query.
    """

    # ICMPv6 MLDv2 Query body (24 bytes after the 4-byte ICMPv6
    # header). Layout from RFC 3810 §5.1:
    #   MRC (2) + Reserved (2) + MulticastAddress (16) +
    #   Resv|S|QRV|QQIC (2) + Number of Sources (2)
    mldv2_query_body = (
        b"\x27\x10"  # MRC = 10000 ms (Maximum Response Code)
        b"\x00\x00"  # Reserved
        + b"\x00" * 16  # Multicast Address = :: (General Query)
        + b"\x02"  # Resv(4)|S(1)|QRV(3) = 0/0/0b010
        + b"\x7d"  # QQIC = 125
        + b"\x00\x00"  # Number of Sources = 0
    )

    icmp6_header_no_cksum = (
        b"\x82"  # Type = 130 (MULTICAST_LISTENER_QUERY)
        b"\x00"  # Code = 0
        b"\x00\x00"  # Checksum (zero for cksum compute)
    )
    icmp6_packet = icmp6_header_no_cksum + mldv2_query_body  # 28 bytes

    # IPv6 pseudo-header per RFC 4443 §2.3:
    #   src (16) + dst (16) + ULP-length (4) + zero (3) + NextHeader=58 (1)
    ip6_src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    ip6_dst = bytes.fromhex("ff020000000000000000000000000001")  # ff02::1
    icmp6_len = len(icmp6_packet)
    pseudo_header = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"

    cksum = inet_cksum(pseudo_header + icmp6_packet)
    icmp6_packet_with_cksum = icmp6_packet[:2] + cksum.to_bytes(2, "big") + icmp6_packet[4:]

    # IPv6 header: version=6, TC=0, FL=0, plen=28, NH=58, hop=1,
    # src=fe80::1, dst=ff02::1
    ip6_header = (
        b"\x60\x00\x00\x00"  # ver|TC|FL = 6,0,0
        + icmp6_len.to_bytes(2, "big")  # Payload Length
        + b"\x3a"  # Next Header = 58 (ICMPv6)
        + b"\x01"  # Hop Limit = 1
        + ip6_src
        + ip6_dst
    )

    # Ethernet header: dst=33:33:00:00:00:01 (IPv6 all-nodes
    # multicast MAC), src=02:00:00:00:00:91 (HOST_A), type=0x86dd
    ethernet_header = (
        b"\x33\x33\x00\x00\x00\x01"  # dst (IPv6 mc all-nodes)
        b"\x02\x00\x00\x00\x00\x91"  # src (HOST_A MAC)
        b"\x86\xdd"  # ethertype = IPv6
    )

    return ethernet_header + ip6_header + icmp6_packet_with_cksum


class TestIcmp6Mld2QueryResponse(IcmpTestCase):
    """
    Verify the §5.1.10 listener-side Query → Report
    response: an inbound MLDv2 General Query drives an
    outbound MLDv2 Report on the wire.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        # Subscribe to the IPv6 all-nodes multicast MAC
        # (33:33:00:00:00:01) so the Ethernet RX filter
        # accepts MLDv2 Queries sent to the all-nodes group.
        # Real PyTCP stacks do this automatically when they
        # join ff02::1; the harness fixture doesn't.
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))

        # RFC 3810 §5.1.10 random-delay window is exercised by
        # the dedicated 'test__icmp6__mld2_query_delay_window'
        # suite; here, force delay=0 so the Report is emitted
        # synchronously and these wire-format assertions stay
        # straightforward.
        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: 0
        )

    def test__icmp6__mld2_query__triggers_report_on_wire(self) -> None:
        """
        Ensure an inbound MLDv2 General Query elicits exactly
        one outbound TX frame (the listener-side Report).

        Reference: RFC 3810 §5.1.10 (listener responds to General Query).
        """

        query_frame = _build_mldv2_general_query_frame()

        frames_tx = self._drive_rx(frame=query_frame)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Expected exactly one TX frame (the listener-side Report); got {len(frames_tx)}: {frames_tx!r}",
        )

    def test__icmp6__mld2_query__increments_query_counter(self) -> None:
        """
        Ensure 'icmp6__mld2_query' counter increments on
        inbound Query receipt.

        Reference: RFC 3810 §5.1.10 (Query RX accounting).
        """

        query_frame = _build_mldv2_general_query_frame()
        before = self._packet_handler._packet_stats_rx.icmp6__mld2_query

        self._drive_rx(frame=query_frame)

        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query,
            before + 1,
            msg="icmp6__mld2_query must increment by 1 per inbound General Query.",
        )

    def test__icmp6__mld2_query__increments_respond_counter(self) -> None:
        """
        Ensure 'icmp6__mld2_query__respond' counter
        increments on Query receipt (one Report sent per
        Query in the Phase-1 immediate-response model).

        Reference: RFC 3810 §5.1.10 (listener responds with Report).
        """

        query_frame = _build_mldv2_general_query_frame()
        before = self._packet_handler._packet_stats_rx.icmp6__mld2_query__respond

        self._drive_rx(frame=query_frame)

        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__respond,
            before + 1,
            msg="icmp6__mld2_query__respond must increment by 1 per Query response.",
        )

    def test__icmp6__mld2_query__report_is_type_143(self) -> None:
        """
        Ensure the TX frame emitted in response to the Query
        is an MLDv2 Report (ICMPv6 type 143), not some other
        ICMPv6 message.

        Reference: RFC 3810 §5.2 (Report message type = 143).
        """

        query_frame = _build_mldv2_general_query_frame()
        frames_tx = self._drive_rx(frame=query_frame)

        # The Report is wrapped in HBH(RA) carrier; locate the
        # ICMPv6 type byte after the ethernet (14) + IPv6 (40)
        # + HBH (8) prefix. The HBH header is 2 bytes plus 6
        # bytes of options (RA + PadN), giving an 8-byte HBH.
        offset_icmp6_type = 14 + 40 + 8
        type_byte = frames_tx[0][offset_icmp6_type]

        self.assertEqual(
            type_byte,
            int(Icmp6Type.MLD2__REPORT),
            msg=f"Expected outbound ICMPv6 type 143 (MLDv2 Report); got {type_byte}.",
        )
