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
Integration tests for the RFC 2710 §4 MLDv1 Report-suppression rule:
a listener with a pending delayed Report that hears another node
report the same multicast address on the link cancels its own Report
for that address, so only one Report per address crosses the link.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld1_report_suppression.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# The stack's own Reports carry a Hop-by-Hop Router Alert header, so
# the ICMPv6 type byte sits after Ethernet(14) + IPv6(40) + HBH(8) and
# the MLDv1 multicast-address field a further ICMPv6 header(4) +
# MRD(2) + Reserved(2) beyond that.
_OFFSET_ICMP6_TYPE = 14 + 40 + 8
_OFFSET_MLD1_GROUP = _OFFSET_ICMP6_TYPE + 8

# A reportable group joined on top of the harness defaults. The
# harness already joins the solicited-node group, which stays
# reportable and acts as the "other group" control.
_GROUP_REPORTED = Ip6Address("ff02::fb")

# Long enough that the scheduled Report is still pending when the
# peer's Report arrives, so the suppression window is open.
_RESPONSE_DELAY_MS = 5_000


def _build_mld1_query_frame() -> bytes:
    """
    Build a 24-octet RFC 2710 §3.1 MLDv1 General Query frame, which
    puts the interface into MLDv1 Host Compatibility Mode.
    """

    # MLDv1 Query body (20 bytes): MRD(2) + Reserved(2) + Addr(16).
    body = b"\x27\x10" + b"\x00\x00" + b"\x00" * 16  # MRD=10000ms, ::
    return _wrap_icmp6(
        icmp6_no_cksum=b"\x82\x00\x00\x00" + body,
        ip6_dst=bytes.fromhex("ff020000000000000000000000000001"),  # ff02::1
        ethernet_dst=b"\x33\x33\x00\x00\x00\x01",
    )


def _build_mld1_report_frame(*, group: Ip6Address) -> bytes:
    """
    Build a 24-octet RFC 2710 §3 MLDv1 Report frame as a peer would
    emit it: sent to the reported group address itself, hop limit 1,
    from a link-local source that is not ours.
    """

    # MLDv1 Report body (20 bytes): MRD(2) + Reserved(2) + Addr(16).
    body = b"\x00\x00" + b"\x00\x00" + bytes(group)
    return _wrap_icmp6(
        icmp6_no_cksum=b"\x83\x00\x00\x00" + body,
        ip6_dst=bytes(group),
        ethernet_dst=bytes(group.multicast_mac),
    )


def _wrap_icmp6(*, icmp6_no_cksum: bytes, ip6_dst: bytes, ethernet_dst: bytes) -> bytes:
    """
    Wrap an ICMPv6 message in IPv6 + Ethernet framing, from a peer's
    link-local address, with the checksum computed over the RFC 2460
    §8.1 pseudo-header.
    """

    ip6_src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    icmp6_len = len(icmp6_no_cksum)
    pseudo = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"
    cksum = inet_cksum(pseudo + icmp6_no_cksum)
    icmp6 = icmp6_no_cksum[:2] + cksum.to_bytes(2, "big") + icmp6_no_cksum[4:]
    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a\x01" + ip6_src + ip6_dst
    ethernet = ethernet_dst + b"\x02\x00\x00\x00\x00\x91" + b"\x86\xdd"
    return ethernet + ip6_header + icmp6


class TestIcmp6Mld1ReportSuppression(IcmpTestCase):
    """
    The RFC 2710 §4 MLDv1 Report-suppression tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))
        self._packet_handler.assign_ip6_multicast(_GROUP_REPORTED)
        # Hold the scheduled Report pending so the peer's Report lands
        # inside the suppression window.
        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: _RESPONSE_DELAY_MS
        )
        # Drop the state-change Report the join above emitted.
        self._frames_tx.clear()

    def _reported_groups(self, frames: list[bytes]) -> set[Ip6Address]:
        """
        Extract the multicast address reported by every MLDv1 Report
        among the supplied outbound frames.
        """

        return {
            Ip6Address(frame[_OFFSET_MLD1_GROUP : _OFFSET_MLD1_GROUP + 16])
            for frame in frames
            if len(frame) >= _OFFSET_MLD1_GROUP + 16
            and frame[_OFFSET_ICMP6_TYPE] == int(Icmp6Type.MULTICAST_LISTENER_REPORT)
        }

    def test__mld1__peer_report_suppresses_own_report_for_that_group(self) -> None:
        """
        Ensure a listener holding a pending MLDv1 Report cancels it for
        a multicast address another node has just reported on the link,
        so the address is not reported twice.

        Reference: RFC 2710 §4 (stop the timer, send no Report).
        """

        self._drive_rx(frame=_build_mld1_query_frame())
        self._drive_rx(frame=_build_mld1_report_frame(group=_GROUP_REPORTED))

        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertNotIn(
            _GROUP_REPORTED,
            self._reported_groups(frames_tx),
            msg=(
                "A group another node reported while our Report was " "pending MUST NOT be reported again by this host."
            ),
        )

    def test__mld1__peer_report_leaves_other_groups_reported(self) -> None:
        """
        Ensure suppression is scoped to the reported multicast address
        alone — every other group the interface listens to is still
        reported when the pending Report fires.

        Reference: RFC 2710 §4 (suppression is per multicast address).
        """

        solicited_node = self._packet_handler._ip6_ifaddr[0].address.solicited_node_multicast

        self._drive_rx(frame=_build_mld1_query_frame())
        self._drive_rx(frame=_build_mld1_report_frame(group=_GROUP_REPORTED))

        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertIn(
            solicited_node,
            self._reported_groups(frames_tx),
            msg=(
                "Suppressing one group MUST NOT suppress the others — "
                "the solicited-node group is still ours to report."
            ),
        )

    def test__mld1__peer_report_outside_the_window_does_not_suppress(self) -> None:
        """
        Ensure a peer Report heard while no Report of ours is pending
        leaves the next Query response untouched, so the suppression
        state cannot leak across response windows.

        Reference: RFC 2710 §4 (suppression applies to a pending timer).
        """

        self._drive_rx(frame=_build_mld1_report_frame(group=_GROUP_REPORTED))
        self._drive_rx(frame=_build_mld1_query_frame())

        frames_tx = self._advance(ms=_RESPONSE_DELAY_MS + 1)

        self.assertIn(
            _GROUP_REPORTED,
            self._reported_groups(frames_tx),
            msg=(
                "A peer Report heard before any Report of ours was "
                "pending MUST NOT suppress the next Query response."
            ),
        )

    def test__mld1__peer_report_does_not_suppress_in_mldv2_mode(self) -> None:
        """
        Ensure the suppression rule is confined to MLDv1 compatibility
        mode. MLDv2 has no Report suppression, so a stray MLDv1 Report
        must not cancel the aggregated MLDv2 Report.

        Reference: RFC 2710 §4 (MLDv1 Report suppression).
        Reference: RFC 3810 §6.1 (MLDv2 removes Report suppression).
        """

        self._drive_rx(frame=_build_mld1_report_frame(group=_GROUP_REPORTED))

        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld1_report__suppressed,
            0,
            msg="Outside MLDv1 compatibility mode a peer Report MUST NOT suppress anything.",
        )
