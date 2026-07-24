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
Smoke tests for the 'IcmpTestCase' integration-test harness using
the canonical IPv6/ICMPv6 Echo Request / Echo Reply roundtrip,
mirroring the IPv4 smoke test. Pins that '_parse_tx_icmp6' and
'_assert_icmp6_message' compose correctly end-to-end so subsequent
ICMP-related work can rely on the harness shape.

pytcp/tests/integration/protocols/icmp6/test__icmp6__harness_smoke.py

ver 3.0.8
"""

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6MessageEchoReply, Icmp6Type
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# Echo data payload pinned by the long-standing canonical Echo
# Request integration case (timestamp prefix + 0x10..0x3f pattern,
# 64 bytes total).
_ECHO_DATA: bytes = (
    b"\x88\x9f\xba\x60\x00\x00\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00"
    b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
)

# ICMPv6 Echo Request from host A (2001:db8:0:1::91) to the stack
# (2001:db8:0:1::7), id=7, seq=10, 64-byte payload — same frame
# the legacy parametrized icmp6__rx integration test drives in.
#   Ethernet : dst=02:00:00:00:00:07, src=02:00:00:00:00:91, type=0x86dd
#   IPv6     : src=2001:db8:0:1::91, dst=2001:db8:0:1::7, hop=64,
#              next=58 (ICMPv6), plen=72
#   ICMPv6   : type=128 (Echo Request), code=0, cksum=0x04ef,
#              id=0x0007, seq=0x000a, data=_ECHO_DATA
_ECHO_REQUEST_FRAME_RX: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x48\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x80\x00\x04\xef\x00\x07\x00\x0a"
) + _ECHO_DATA


class TestIcmp6HarnessSmoke(IcmpTestCase):
    """
    Smoke tests for 'IcmpTestCase' on the IPv6 Echo path.
    """

    def test__icmp6__harness__echo_request_drives_one_reply(self) -> None:
        """
        Ensure '_drive_rx' on a valid IPv6 Echo Request returns
        exactly one TX frame — the harness contract for "RX in,
        captured TX out".

        Reference: RFC 4443 §4.1 (Echo Request).
        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        frames_tx = self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Expected exactly one TX frame for the Echo Request, got {len(frames_tx)}: {frames_tx!r}",
        )

    def test__icmp6__harness__echo_reply_decodes_into_probe(self) -> None:
        """
        Ensure '_parse_tx_icmp6' decodes the outbound Echo Reply
        frame into an 'Icmp6Probe' whose id, seq and data fields
        mirror the request, whose IP source and destination swap
        relative to the request, and whose hop limit is 255.

        Reference: RFC 4443 §4.2 (Echo Reply).
        Reference: RFC 4443 §2.4 (Hop Limit on outbound).
        """

        frames_tx = self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ECHO_REPLY),
            code=0,
            id=7,
            seq=10,
            mtu=None,
            target=None,
            data=_ECHO_DATA,
            ip_src=Ip6Address("2001:db8:0:1::7"),
            ip_dst=Ip6Address("2001:db8:0:1::91"),
            ip_hop=255,
        )

    def test__icmp6__harness__echo_reply_decodes_ip_layer_fields(self) -> None:
        """
        Ensure the probe captures the full IPv6 header observable
        surface (DSCP, ECN, flow label) so migrated tests can pin
        every field that the legacy byte-equality matrix used to
        cover.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frames_tx = self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self._assert_icmp6_message(
            probe,
            ip_dscp=0,
            ip_ecn=0,
            ip_flow=0,
        )

    def test__icmp6__harness__echo_reply_decodes_ethernet_addresses(self) -> None:
        """
        Ensure the probe captures the Ethernet source and destination
        the stack actually emitted, so migrated tests can pin link-
        layer addressing without comparing whole frames.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frames_tx = self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self._assert_icmp6_message(
            probe,
            eth_src=MacAddress("02:00:00:00:00:07"),
            eth_dst=MacAddress("02:00:00:00:00:91"),
        )

    def test__icmp6__harness__echo_reply_exposes_parsed_message(self) -> None:
        """
        Ensure '_parse_tx_icmp6' attaches the decoded 'Icmp6Message'
        object so tests can read message-type-specific fields (NA
        flags, RA options, MLD2 records) without forcing the probe
        to enumerate every variant.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frames_tx = self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self.assertIsInstance(
            probe.message,
            Icmp6MessageEchoReply,
            msg=f"probe.message must be an Icmp6MessageEchoReply for an Echo path: {probe!r}",
        )

    def test__icmp6__harness__packet_stats_rx_strict_match(self) -> None:
        """
        Ensure '_assert_packet_stats_rx' enforces strict equality by
        default on the IPv6 path: every counter not named in the
        helper call must be zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__echo_request__respond_echo_reply=1,
        )

    def test__icmp6__harness__packet_stats_tx_strict_match(self) -> None:
        """
        Ensure '_assert_packet_stats_tx' enforces strict equality by
        default on the IPv6 path, mirroring the byte-equality
        regression net of the legacy parametrized integration tests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__echo_reply__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
        )

    def test__icmp6__harness__packet_stats_loose_mode_ignores_extras(self) -> None:
        """
        Ensure '_assert_packet_stats_rx' with exact=False checks only
        the named counters and does not fail when other counters are
        non-zero — escape hatch for tests that intentionally only
        pin a subset.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_ECHO_REQUEST_FRAME_RX)

        self._assert_packet_stats_rx(
            exact=False,
            icmp6__pre_parse=1,
        )
