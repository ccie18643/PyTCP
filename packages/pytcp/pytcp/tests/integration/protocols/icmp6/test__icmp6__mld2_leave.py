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
Integration tests for MLDv2 leave reporting (RFC 3810 §5.2 / §6.1):
leaving an IPv6 multicast group emits a State Change Report carrying a
CHANGE_TO_INCLUDE record with an empty source list (the MLDv2 leave
signal), the IPv6 analogue of the shipped IGMP leave. While the
interface is in MLDv1 Host Compatibility Mode (RFC 3810 §8) a leave is
announced with an MLDv1 Done (type 132) instead. Stack shutdown
gracefully leaves every joined group except all-nodes (ff02::1).

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_leave.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# Ethernet(14) + IPv6(40) + HBH(8) — the ICMPv6 message starts here.
_OFFSET_ICMP6 = 14 + 40 + 8
# IPv6 destination address sits at Ethernet(14) + 24 within the IPv6 header.
_OFFSET_IP6_DST = 14 + 24
# MLDv2 Report header: type(1) code(1) cksum(2) reserved(2) nr_records(2).
_OFFSET_MLD2_NR_RECORDS = _OFFSET_ICMP6 + 6
_OFFSET_MLD2_FIRST_RECORD = _OFFSET_ICMP6 + 8

_ALL_MLDV2_ROUTERS = Ip6Address("ff02::16")
_ALL_ROUTERS = Ip6Address("ff02::2")
_ALL_NODES = Ip6Address("ff02::1")
# RFC 3810 §5.2.12 Multicast Address Record types.
_RECORD_CHANGE_TO_INCLUDE = 3

_TEST_GROUP_A = Ip6Address("ff02::abcd")
_TEST_GROUP_B = Ip6Address("ff05::1:3")


def _build_mld1_query_frame() -> bytes:
    """
    Build a 24-octet RFC 2710 §3.1 MLDv1 General Query frame (ICMPv6
    type 130 to ff02::1, hop 1, from a router link-local source) — used
    to drive the interface into MLDv1 Host Compatibility Mode.
    """

    # MLDv1 Query body (20 bytes): MRD(2) + Reserved(2) + Addr(16).
    body = b"\x27\x10" + b"\x00\x00" + b"\x00" * 16  # MRD=10000ms, ::
    icmp6_no_cksum = b"\x82\x00\x00\x00" + body
    ip6_src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    ip6_dst = bytes.fromhex("ff020000000000000000000000000001")  # ff02::1
    icmp6_len = len(icmp6_no_cksum)
    pseudo = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"
    cksum = inet_cksum(pseudo + icmp6_no_cksum)
    icmp6 = icmp6_no_cksum[:2] + cksum.to_bytes(2, "big") + icmp6_no_cksum[4:]
    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a\x01" + ip6_src + ip6_dst
    ethernet = b"\x33\x33\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x91" + b"\x86\xdd"
    return ethernet + ip6_header + icmp6


def _parse_mld2_records(frame: bytes) -> dict[Ip6Address, int]:
    """
    Parse an MLDv2 Report frame's Multicast Address Records into a
    {group: record_type} map. Assumes zero aux-data and zero sources
    per record (the shape a filter-mode-change leave/join uses), so
    each record is a fixed 20 octets: type(1) aux(1) nr_sources(2)
    multicast_address(16).
    """

    nr_records = int.from_bytes(frame[_OFFSET_MLD2_NR_RECORDS : _OFFSET_MLD2_NR_RECORDS + 2], "big")
    records: dict[Ip6Address, int] = {}
    pos = _OFFSET_MLD2_FIRST_RECORD
    for _ in range(nr_records):
        record_type = frame[pos]
        group = Ip6Address(bytes(frame[pos + 4 : pos + 20]))
        records[group] = record_type
        pos += 20
    return records


class TestIcmp6Mld2Leave(IcmpTestCase):
    """
    The MLDv2 leave-reporting tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))

    def test__mld2_leave__emits_change_to_include_report(self) -> None:
        """
        Ensure leaving a joined IPv6 multicast group emits a single
        MLDv2 State Change Report (type 143) to the all-MLDv2-routers
        address (ff02::16) carrying a CHANGE_TO_INCLUDE record with an
        empty source list for the departed group.

        Reference: RFC 3810 §5.2.12 (CHANGE_TO_INCLUDE filter-mode-change record).
        Reference: RFC 3810 §6.1 (leaving a group is a state-change Report).
        """

        self._packet_handler.assign_ip6_multicast(_TEST_GROUP_A)

        before = len(self._frames_tx)
        self._packet_handler.remove_ip6_multicast(_TEST_GROUP_A)
        frames_tx = list(self._frames_tx[before:])

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"A group leave must emit exactly one MLD leave frame. Got: {len(frames_tx)}.",
        )
        frame = frames_tx[0]
        self.assertEqual(
            frame[_OFFSET_ICMP6],
            int(Icmp6Type.MLD2__REPORT),
            msg="A leave must be announced as an MLDv2 Report (type 143).",
        )
        self.assertEqual(
            Ip6Address(bytes(frame[_OFFSET_IP6_DST : _OFFSET_IP6_DST + 16])),
            _ALL_MLDV2_ROUTERS,
            msg="An MLDv2 leave Report must be sent to ff02::16 (all-MLDv2-routers).",
        )
        records = _parse_mld2_records(frame)
        self.assertEqual(
            records.get(_TEST_GROUP_A),
            _RECORD_CHANGE_TO_INCLUDE,
            msg="The leave Report must carry a CHANGE_TO_INCLUDE record for the departed group.",
        )
        # nr_sources for the departed group's record must be zero.
        pos = _OFFSET_MLD2_FIRST_RECORD
        self.assertEqual(
            int.from_bytes(frame[pos + 2 : pos + 4], "big"),
            0,
            msg="A CHANGE_TO_INCLUDE leave record must carry an empty source list.",
        )

    def test__mld1_compat__leave_emits_mld1_done(self) -> None:
        """
        Ensure that while the interface is in MLDv1 Host Compatibility
        Mode, leaving a group is announced with an MLDv1 Done (ICMPv6
        type 132) to the all-routers address (ff02::2), not an MLDv2
        Report, so an MLDv1-only querier can parse the departure.

        Reference: RFC 3810 §8.3.2 (emit MLDv1 Done while in v1 mode).
        Reference: RFC 2710 §3 (MLDv1 Done sent to ff02::2).
        """

        self._packet_handler.assign_ip6_multicast(_TEST_GROUP_A)
        # Drive the interface into MLDv1 compatibility mode.
        self._drive_rx(frame=_build_mld1_query_frame())

        before = len(self._frames_tx)
        self._packet_handler.remove_ip6_multicast(_TEST_GROUP_A)
        frames_tx = list(self._frames_tx[before:])

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"A leave in MLDv1 mode must emit exactly one Done frame. Got: {len(frames_tx)}.",
        )
        frame = frames_tx[0]
        self.assertEqual(
            frame[_OFFSET_ICMP6],
            int(Icmp6Type.MULTICAST_LISTENER_DONE),
            msg="In MLDv1 compatibility mode a leave must be an MLDv1 Done (type 132).",
        )
        self.assertEqual(
            Ip6Address(bytes(frame[_OFFSET_IP6_DST : _OFFSET_IP6_DST + 16])),
            _ALL_ROUTERS,
            msg="An MLDv1 Done must be sent to ff02::2 (all-routers).",
        )

    def test__mld_leave_all__reports_joined_groups_except_all_nodes(self) -> None:
        """
        Ensure the shutdown graceful-leave path emits an MLDv2 State
        Change Report carrying a CHANGE_TO_INCLUDE record for every
        joined group while never announcing a leave for the all-nodes
        group (ff02::1), which the host must not report.

        Reference: RFC 3810 §6.1 (graceful leave on shutdown).
        Reference: RFC 3810 §6 (all-nodes ff02::1 is never reported).
        """

        self._packet_handler.assign_ip6_multicast(_TEST_GROUP_A)
        self._packet_handler.assign_ip6_multicast(_TEST_GROUP_B)

        before = len(self._frames_tx)
        self._packet_handler.send_mld_leave_all()
        frames_tx = list(self._frames_tx[before:])

        self.assertGreaterEqual(
            len(frames_tx),
            1,
            msg="Shutdown leave-all must emit at least one MLDv2 leave Report.",
        )
        records: dict[Ip6Address, int] = {}
        for frame in frames_tx:
            self.assertEqual(
                frame[_OFFSET_ICMP6],
                int(Icmp6Type.MLD2__REPORT),
                msg="Each shutdown leave frame must be an MLDv2 Report (type 143).",
            )
            records.update(_parse_mld2_records(frame))

        self.assertEqual(
            records.get(_TEST_GROUP_A),
            _RECORD_CHANGE_TO_INCLUDE,
            msg="Leave-all must carry a CHANGE_TO_INCLUDE record for group A.",
        )
        self.assertEqual(
            records.get(_TEST_GROUP_B),
            _RECORD_CHANGE_TO_INCLUDE,
            msg="Leave-all must carry a CHANGE_TO_INCLUDE record for group B.",
        )
        self.assertNotIn(
            _ALL_NODES,
            records,
            msg="Leave-all must never announce a leave for the all-nodes group (ff02::1).",
        )
