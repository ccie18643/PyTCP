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
Integration tests for the record form of the MLDv2 response to a General
Query: it is a Current-State Report, so each Multicast Address Record
carries MODE_IS_INCLUDE / MODE_IS_EXCLUDE and the address's real source
list — not the CHANGE_TO_* State-Change form, which would report an
INCLUDE-mode (SSM) listener as accept-all.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__current_state_report.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp import stack
from pytcp.lib.ip6_multicast_filter import Ip6MulticastFilter, Ip6MulticastFilterMode
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# The stack's own Reports carry a Hop-by-Hop Router Alert header.
_OFFSET_ICMP6 = 14 + 40 + 8
_OFFSET_NR_RECORDS = _OFFSET_ICMP6 + 6
_OFFSET_FIRST_RECORD = _OFFSET_ICMP6 + 8

_ALL_NODES = Ip6Address("ff02::1")
_GROUP_SSM = Ip6Address("ff02::fb")
_SRC_A = Ip6Address("2001:db8::a")
_SRC_B = Ip6Address("2001:db8::b")
_TOKEN = 4242


def _build_general_query_frame() -> bytes:
    """
    Build an RFC 3810 §5.1 MLDv2 General Query (unspecified multicast
    address) addressed to all-nodes, with a zero Maximum Response Code
    so the response emits synchronously.
    """

    # MLDv2 Query body: MRC(2) + Resv(2) + Addr(16) + S/QRV(1) + QQIC(1)
    # + Nr of Sources(2). MRC 0 => respond immediately.
    body = b"\x00\x00" + b"\x00\x00" + bytes(Ip6Address()) + b"\x02" + b"\x7d" + b"\x00\x00"
    icmp6_no_cksum = b"\x82\x00\x00\x00" + body
    ip6_src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    ip6_dst = bytes(_ALL_NODES)
    icmp6_len = len(icmp6_no_cksum)
    pseudo = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"
    cksum = inet_cksum(pseudo + icmp6_no_cksum)
    icmp6 = icmp6_no_cksum[:2] + cksum.to_bytes(2, "big") + icmp6_no_cksum[4:]
    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a\x01" + ip6_src + ip6_dst
    ethernet = bytes(_ALL_NODES.multicast_mac) + b"\x02\x00\x00\x00\x00\x91" + b"\x86\xdd"
    return ethernet + ip6_header + icmp6


def _records(frame: bytes) -> dict[Ip6Address, tuple[int, frozenset[Ip6Address]]]:
    """
    Decode an MLDv2 Report frame into {address: (record type, sources)},
    walking the variable-length per-record source lists.
    """

    decoded: dict[Ip6Address, tuple[int, frozenset[Ip6Address]]] = {}
    offset = _OFFSET_FIRST_RECORD
    for _ in range(int.from_bytes(frame[_OFFSET_NR_RECORDS : _OFFSET_NR_RECORDS + 2], "big")):
        if offset + 20 > len(frame):
            break
        record_type = frame[offset]
        nr_sources = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        group = Ip6Address(frame[offset + 4 : offset + 20])
        sources = frozenset(Ip6Address(frame[offset + 20 + 16 * i : offset + 36 + 16 * i]) for i in range(nr_sources))
        decoded[group] = (record_type, sources)
        offset += 20 + 16 * nr_sources
    return decoded


class TestIcmp6MldCurrentStateReport(IcmpTestCase):
    """
    The MLDv2 Current-State Report record-form tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))

    def _drive_query(self) -> dict[Ip6Address, tuple[int, frozenset[Ip6Address]]]:
        """
        Drive a General Query and decode the records of the single
        MLDv2 Report it elicits.
        """

        self._packet_handler._icmp6_tx._cancel_mld_state_change_retransmits()
        self._frames_tx.clear()

        frames_tx = self._drive_rx(frame=_build_general_query_frame())
        reports = [
            frame
            for frame in frames_tx
            if len(frame) > _OFFSET_ICMP6 and frame[_OFFSET_ICMP6] == int(Icmp6Type.MLD2__REPORT)
        ]
        self.assertEqual(
            len(reports),
            1,
            msg=f"A General Query must elicit exactly one MLDv2 Report; got {len(reports)}.",
        )
        return _records(reports[0])

    def test__mld2__general_query_response__uses_current_state_record_type(self) -> None:
        """
        Ensure the response to a General Query carries MODE_IS_EXCLUDE
        for an any-source listener, the Current-State record form, and
        not the CHANGE_TO_EXCLUDE State-Change form.

        Reference: RFC 3810 §5.2.12 (Current-State Record types).
        Reference: RFC 3810 §6.1 (Query response is a Current-State Report).
        """

        solicited_node = self._packet_handler._ip6_ifaddr[0].address.solicited_node_multicast

        records = self._drive_query()

        self.assertEqual(
            records[solicited_node][0],
            int(Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE),
            msg=(
                "An any-source listener must be reported with the "
                "MODE_IS_EXCLUDE Current-State record on a Query response."
            ),
        )

    def test__mld2__general_query_response__include_filter_keeps_its_sources(self) -> None:
        """
        Ensure a source-specific listener is reported as MODE_IS_INCLUDE
        carrying its source list, so a router forwards only the sources
        actually asked for rather than every source.

        Reference: RFC 3810 §5.2.12 (Current-State Record types).
        Reference: RFC 3810 §4.2 (per-address filter mode and source list).
        """

        stack.membership6.set_socket_filter(
            group=_GROUP_SSM,
            token=_TOKEN,
            source_filter=Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_SRC_A, _SRC_B})),
        )

        records = self._drive_query()

        self.assertEqual(
            records[_GROUP_SSM],
            (int(Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE), frozenset({_SRC_A, _SRC_B})),
            msg=(
                "An INCLUDE-mode listener must be reported as "
                "MODE_IS_INCLUDE with its source list, never as accept-all."
            ),
        )
