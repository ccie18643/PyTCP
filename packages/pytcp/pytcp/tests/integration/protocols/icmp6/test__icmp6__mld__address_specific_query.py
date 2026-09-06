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
Integration tests for the listener-side response to an MLD Multicast
Address Specific Query: the response covers only the queried address,
scheduled on a per-address timer, mirroring the IGMP Group-Specific
Query handling on the IPv4 side.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__address_specific_query.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# The stack's own Reports carry a Hop-by-Hop Router Alert header, so the
# ICMPv6 message starts after Ethernet(14) + IPv6(40) + HBH(8).
_OFFSET_ICMP6 = 14 + 40 + 8
# MLDv2 Report: ICMPv6 header(4) + Reserved(2) + Nr of Records(2).
_OFFSET_MLD2_NR_RECORDS = _OFFSET_ICMP6 + 6
_OFFSET_MLD2_FIRST_RECORD = _OFFSET_ICMP6 + 8
# MLDv1 Report: ICMPv6 header(4) + Max Response Delay(2) + Reserved(2).
_OFFSET_MLD1_GROUP = _OFFSET_ICMP6 + 8

_ALL_NODES = Ip6Address("ff02::1")
# A reportable group joined on top of the harness defaults; the
# solicited-node group the harness joins is the "other group" control.
_GROUP_QUERIED = Ip6Address("ff02::fb")
_GROUP_NOT_JOINED = Ip6Address("ff02::dead")

# Long enough that the response is still pending when the test advances.
_RESPONSE_DELAY_MS = 5_000


def _build_mld2_query_frame(*, group: Ip6Address) -> bytes:
    """
    Build an RFC 3810 §5.1 MLDv2 Query. An unspecified 'group' is a
    General Query addressed to all-nodes; any other address is a
    Multicast Address Specific Query addressed to the group itself.
    """

    # MLDv2 Query body: MRC(2) + Resv(2) + Addr(16) + S/QRV(1) + QQIC(1)
    # + Nr of Sources(2).
    body = b"\x27\x10" + b"\x00\x00" + bytes(group) + b"\x02" + b"\x7d" + b"\x00\x00"
    return _wrap_query(icmp6_no_cksum=b"\x82\x00\x00\x00" + body, group=group)


def _build_mld1_query_frame(*, group: Ip6Address) -> bytes:
    """
    Build a 24-octet RFC 2710 §3.1 MLDv1 Query. An unspecified 'group'
    is a General Query; any other address is a Multicast Address
    Specific Query.
    """

    # MLDv1 Query body: MRD(2) + Reserved(2) + Addr(16).
    body = b"\x27\x10" + b"\x00\x00" + bytes(group)
    return _wrap_query(icmp6_no_cksum=b"\x82\x00\x00\x00" + body, group=group)


def _wrap_query(*, icmp6_no_cksum: bytes, group: Ip6Address) -> bytes:
    """
    Wrap an MLD Query in IPv6 + Ethernet framing from a router's
    link-local address. A General Query goes to all-nodes; an
    address-specific one to the queried group.
    """

    destination = _ALL_NODES if group.is_unspecified else group
    ip6_src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    ip6_dst = bytes(destination)
    icmp6_len = len(icmp6_no_cksum)
    pseudo = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"
    cksum = inet_cksum(pseudo + icmp6_no_cksum)
    icmp6 = icmp6_no_cksum[:2] + cksum.to_bytes(2, "big") + icmp6_no_cksum[4:]
    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a\x01" + ip6_src + ip6_dst
    ethernet = bytes(destination.multicast_mac) + b"\x02\x00\x00\x00\x00\x91" + b"\x86\xdd"
    return ethernet + ip6_header + icmp6


class TestIcmp6MldAddressSpecificQuery(IcmpTestCase):
    """
    The MLD Multicast Address Specific Query response tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))
        self._packet_handler._mac_multicast.append(_GROUP_QUERIED.multicast_mac)
        self._packet_handler.assign_ip6_multicast(_GROUP_QUERIED)
        # The join arms an RFC 3810 §9.1 robustness retransmit train;
        # cancel it so only Query responses reach the wire.
        self._packet_handler._icmp6_tx._cancel_mld_state_change_retransmits()
        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: _RESPONSE_DELAY_MS
        )
        self._frames_tx.clear()

    def _reported_groups(self, frames: list[bytes]) -> set[Ip6Address]:
        """
        Collect every multicast address reported across the supplied
        outbound frames, from either Report form.
        """

        groups: set[Ip6Address] = set()
        for frame in frames:
            if len(frame) <= _OFFSET_ICMP6:
                continue
            if frame[_OFFSET_ICMP6] == int(Icmp6Type.MULTICAST_LISTENER_REPORT):
                groups.add(Ip6Address(frame[_OFFSET_MLD1_GROUP : _OFFSET_MLD1_GROUP + 16]))
            elif frame[_OFFSET_ICMP6] == int(Icmp6Type.MLD2__REPORT):
                groups |= _mld2_record_groups(frame)
        return groups

    def test__mld2__address_specific_query__reports_only_the_queried_group(self) -> None:
        """
        Ensure a Multicast Address Specific Query is answered with a
        Report covering that address alone, rather than the interface's
        entire membership.

        Reference: RFC 3810 §5.1.13 (address-specific Query semantics).
        Reference: RFC 3810 §6.1 (per-address response timer).
        """

        self._drive_rx(frame=_build_mld2_query_frame(group=_GROUP_QUERIED))
        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertEqual(
            self._reported_groups(frames_tx),
            {_GROUP_QUERIED},
            msg=(
                "A Multicast Address Specific Query must elicit a Report "
                "for the queried address only, not the whole membership."
            ),
        )

    def test__mld2__address_specific_query__unjoined_group_elicits_no_report(self) -> None:
        """
        Ensure a Query for an address the interface has no reception
        state for is answered with silence.

        Reference: RFC 3810 §6.1 (respond only where reception state exists).
        """

        self._drive_rx(frame=_build_mld2_query_frame(group=_GROUP_NOT_JOINED))
        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertNotIn(
            _GROUP_NOT_JOINED,
            self._reported_groups(frames_tx),
            msg="An address the interface does not listen to must never be reported.",
        )

    def test__mld2__general_query__still_reports_every_group(self) -> None:
        """
        Ensure a General Query keeps eliciting the aggregated Report
        covering every joined address, so the address-specific path
        does not narrow the general one.

        Reference: RFC 3810 §5.1.13 (General Query covers all addresses).
        """

        solicited_node = self._packet_handler._ip6_ifaddr[0].address.solicited_node_multicast

        self._drive_rx(frame=_build_mld2_query_frame(group=Ip6Address()))
        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertEqual(
            self._reported_groups(frames_tx),
            {_GROUP_QUERIED, solicited_node},
            msg="A General Query must still report every joined group.",
        )

    def test__mld1__address_specific_query__reports_only_the_queried_group(self) -> None:
        """
        Ensure the address-specific response also holds in MLDv1
        compatibility mode, where the reply is a per-address MLDv1
        Report rather than an aggregated MLDv2 one.

        Reference: RFC 2710 §4 (address-specific Query semantics).
        Reference: RFC 3810 §8.3.1 (MLDv1 Report form while in v1 mode).
        """

        self._drive_rx(frame=_build_mld1_query_frame(group=_GROUP_QUERIED))
        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertEqual(
            self._reported_groups(frames_tx),
            {_GROUP_QUERIED},
            msg=(
                "In MLDv1 compatibility mode an address-specific Query "
                "must elicit a Report for the queried address only."
            ),
        )


def _mld2_record_groups(frame: bytes) -> set[Ip6Address]:
    """
    Extract the multicast address of every Multicast Address Record in
    an MLDv2 Report frame, walking the variable-length source lists.
    """

    groups: set[Ip6Address] = set()
    offset = _OFFSET_MLD2_FIRST_RECORD
    for _ in range(int.from_bytes(frame[_OFFSET_MLD2_NR_RECORDS : _OFFSET_MLD2_NR_RECORDS + 2], "big")):
        if offset + 20 > len(frame):
            break
        nr_sources = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        groups.add(Ip6Address(frame[offset + 4 : offset + 20]))
        offset += 20 + 16 * nr_sources
    return groups
