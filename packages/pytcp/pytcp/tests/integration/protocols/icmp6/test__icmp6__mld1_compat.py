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
Integration tests for the RFC 3810 §8 MLDv1 compatibility fallback:
hearing a 24-octet MLDv1 Query puts the interface into MLDv1 Host
Compatibility Mode, in which the listener emits MLDv1 Reports
(type 131) instead of the MLDv2 Report (type 143); the mode reverts
to MLDv2 after the Older Version Querier Present timeout.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld1_compat.py

ver 3.0.9
"""

from typing import override

from net_addr import MacAddress
from net_proto import Icmp6Type
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import MldVersion
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# ICMPv6 type byte sits after Ethernet(14) + IPv6(40) + HBH(8).
_OFFSET_ICMP6_TYPE = 14 + 40 + 8


def _build_mld_query_frame(*, mldv1: bool) -> bytes:
    """
    Build an MLD General Query frame. With 'mldv1' True the body is
    the 24-octet RFC 2710 §3.1 MLDv1 form (Max Resp Delay + Reserved +
    Multicast Address); otherwise the 28-octet RFC 3810 §5.1 MLDv2
    form. Both are ICMPv6 type 130 to ff02::1, hop 1, from a router
    link-local source.
    """

    if mldv1:
        # MLDv1 Query body (20 bytes): MRD(2) + Reserved(2) + Addr(16).
        body = b"\x27\x10" + b"\x00\x00" + b"\x00" * 16  # MRD=10000ms, ::
    else:
        # MLDv2 Query body (24 bytes): MRC(2)+Resv(2)+Addr(16)+flags(2)+N(2).
        body = b"\x27\x10" + b"\x00\x00" + b"\x00" * 16 + b"\x02" + b"\x7d" + b"\x00\x00"

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


class TestIcmp6Mld1Compat(IcmpTestCase):
    """
    The RFC 3810 §8 MLDv1 compatibility-fallback tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))
        # Force the query-response delay to 0 so Reports emit
        # synchronously and the wire-form assertions stay simple.
        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: 0
        )

    def test__mld1_query__enters_v1_mode_and_emits_v1_report(self) -> None:
        """
        Ensure an inbound 24-octet MLDv1 Query puts the interface into
        MLDv1 Host Compatibility Mode and the listener responds with an
        MLDv1 Report (ICMPv6 type 131), not an MLDv2 Report (type 143).

        Reference: RFC 3810 §8.2.1 (enter MLDv1 mode on an MLDv1 Query).
        Reference: RFC 3810 §8.3.1 (emit MLDv1 Reports while in v1 mode).
        """

        frames_tx = self._drive_rx(frame=_build_mld_query_frame(mldv1=True))

        self.assertGreaterEqual(
            len(frames_tx),
            1,
            msg="An MLDv1 Query must elicit at least one MLDv1 Report.",
        )
        self.assertEqual(
            frames_tx[0][_OFFSET_ICMP6_TYPE],
            int(Icmp6Type.MULTICAST_LISTENER_REPORT),
            msg=(
                "In MLDv1 compatibility mode the response Report must be "
                f"type 131 (MLDv1), not 143. Got: {frames_tx[0][_OFFSET_ICMP6_TYPE]}."
            ),
        )

    def test__mld2_query__stays_v2_and_emits_v2_report(self) -> None:
        """
        Ensure a 28-octet MLDv2 Query keeps the interface in MLDv2 mode
        and the response is an MLDv2 Report (type 143). Regression guard
        that the length-discriminated dispatch does not mistake an
        MLDv2 Query for the v1 form.

        Reference: RFC 3810 §8.1 (MLDv2 Query is >= 28 octets).
        """

        frames_tx = self._drive_rx(frame=_build_mld_query_frame(mldv1=False))

        self.assertGreaterEqual(len(frames_tx), 1, msg="An MLDv2 Query must elicit a Report.")
        self.assertEqual(
            frames_tx[0][_OFFSET_ICMP6_TYPE],
            int(Icmp6Type.MLD2__REPORT),
            msg=(
                "An MLDv2 Query must keep MLDv2 mode and emit a type-143 "
                f"Report. Got: {frames_tx[0][_OFFSET_ICMP6_TYPE]}."
            ),
        )

    def test__mld1_mode_reverts_to_v2_after_timeout(self) -> None:
        """
        Ensure the interface reverts to MLDv2 mode once the Older
        Version Querier Present timeout elapses: after an MLDv1 Query
        and a long clock advance, a fresh MLDv2 Query elicits a
        type-143 MLDv2 Report again.

        Reference: RFC 3810 §8.2.1 (revert to MLDv2 after the timeout).
        """

        self._drive_rx(frame=_build_mld_query_frame(mldv1=True))

        # Advance well past the Older Version Querier Present timeout
        # ([Robustness] x [Query Interval] + [Query Response Interval]).
        self._advance(ms=10 * 60 * 1000)

        frames_tx = self._drive_rx(frame=_build_mld_query_frame(mldv1=False))
        self.assertGreaterEqual(len(frames_tx), 1, msg="An MLDv2 Query must elicit a Report.")
        self.assertEqual(
            frames_tx[0][_OFFSET_ICMP6_TYPE],
            int(Icmp6Type.MLD2__REPORT),
            msg=(
                "After the MLDv1 querier-present timeout the mode must revert "
                f"to MLDv2 (type-143 Report). Got: {frames_tx[0][_OFFSET_ICMP6_TYPE]}."
            ),
        )


class TestIcmp6MldForcedVersion(IcmpTestCase):
    """
    The 'mld.version' forced MLD Host Compatibility Mode tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))
        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: 0
        )

    def test__mld__forced_version_pins_mode(self) -> None:
        """
        Ensure a forced 'mld.version' sysctl pins the MLD Host
        Compatibility Mode regardless of the queriers heard: value 1 pins
        MLDv1, value 2 pins MLDv2, and the default 0 leaves the automatic
        querier-tracking fallback in effect.

        Reference: RFC 3810 §8.3.1 (host compatibility mode selects the report version).
        """

        self.assertIs(
            self._packet_handler._mld_host_compatibility_mode(),
            MldVersion.V2,
            msg="With 'mld.version' at its default 0 the interface must start in MLDv2 mode.",
        )
        with sysctl.override("mld.version", 1):
            self.assertIs(
                self._packet_handler._mld_host_compatibility_mode(),
                MldVersion.V1,
                msg="A forced 'mld.version' of 1 must pin the interface to MLDv1 mode.",
            )
        with sysctl.override("mld.version", 2):
            self.assertIs(
                self._packet_handler._mld_host_compatibility_mode(),
                MldVersion.V2,
                msg="A forced 'mld.version' of 2 must pin the interface to MLDv2 mode.",
            )

    def test__mld__forced_v1__query_response_is_v1_report(self) -> None:
        """
        Ensure that with 'mld.version' forced to 1 an inbound MLDv2 Query
        elicits an MLDv1 Report (ICMPv6 type 131), the forced mode
        overriding the version implied by the query heard.

        Reference: RFC 3810 §8.3.1 (emit MLDv1 Reports while in v1 mode).
        """

        with sysctl.override("mld.version", 1):
            frames_tx = self._drive_rx(frame=_build_mld_query_frame(mldv1=False))

        self.assertGreaterEqual(len(frames_tx), 1, msg="A Query must elicit at least one Report.")
        self.assertEqual(
            frames_tx[0][_OFFSET_ICMP6_TYPE],
            int(Icmp6Type.MULTICAST_LISTENER_REPORT),
            msg=(
                "With 'mld.version' forced to 1 the response Report must be "
                f"type 131 (MLDv1), not 143. Got: {frames_tx[0][_OFFSET_ICMP6_TYPE]}."
            ),
        )
