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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Fluent integration tests for the IPv6/ICMPv6 RX path. Mirrors every
parametrized + standalone case in
'pytcp/tests/integration/packet_handler/test__packet_handler__icmp6__rx.py' onto
the 'IcmpTestCase' harness.

pytcp/tests/integration/protocols/icmp6/test__icmp6__rx.py

ver 3.0.8
"""

from typing import Any, override

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6Type
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# 64-byte echo data — timestamp prefix + 0x10..0x3f pattern.
_ECHO_DATA: bytes = (
    b"\x88\x9f\xba\x60\x00\x00\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00"
    b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
)

# ICMPv6 Echo Request from host A (2001:db8:0:1::91) to the stack.
_FRAME_RX__ECHO_REQUEST: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x48\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x80\x00\x04\xef\x00\x07\x00\x0a"
) + _ECHO_DATA

# ICMPv6 Echo Reply from host A with no matching raw socket.
_FRAME_RX__ECHO_REPLY_NO_SOCKET: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x0d\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x81\x00\xde\xc8\x00\x07\x00\x0a\x68\x65"
    b"\x6c\x6c\x6f"
)

# ICMPv6 NS unicast dst with SLLA option.
_FRAME_RX__NS_UNICAST_WITH_SLLA: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x87\x00\xeb\x45\x00\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x01\x01"
    b"\x02\x00\x00\x00\x00\x91"
)

# ICMPv6 NS to solicited-node multicast, no SLLA.
_FRAME_RX__NS_MULTICAST_NO_SLLA: bytes = (
    b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x18\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x01\xff\x00\x00\x07\x87\x00\x1e\x95\x00\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07"
)

# ICMPv6 NS to solicited-node multicast, with SLLA.
_FRAME_RX__NS_MULTICAST_WITH_SLLA: bytes = (
    b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x01\xff\x00\x00\x07\x87\x00\x1a\xfb\x00\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x01\x01"
    b"\x02\x00\x00\x00\x00\x91"
)

# ICMPv6 NS DAD probe — source IP is ::, target=2001:db8:0:1::7.
_FRAME_RX__NS_DAD: bytes = (
    b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x18\x3a\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x01\xff\x00\x00\x07\x87\x00\x4c\xe0\x00\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07"
)

# ICMPv6 Destination Unreachable carrying valid embedded IPv6+UDP
# but no UDP socket matches.
_FRAME_RX__DST_UNREACH_NO_SOCKET: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x38\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x01\x04\xd0\xb5\x00\x00\x00\x00\x60\x00"
    b"\x00\x00\x00\x08\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x30\x39\xd4\x31\x00\x08\x00\x00"
)

# ICMPv6 Destination Unreachable whose embedded data is 48 zero
# bytes (frame[0]>>4 == 0, fails IPv6 version check).
_FRAME_RX__DST_UNREACH_BAD_EMBEDDED: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x38\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x01\x04\xa2\x7d\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

# ICMPv6 Router Advertisement carrying a single Prefix Information
# option (2001:db8:0:abcd::/64, L+A flags set).
_FRAME_RX__ROUTER_ADVERTISEMENT: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x30\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x86\x00\x20\xbe\x40\x00\x07\x08\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x03\x04\x40\xc0\x00\x27\x8d\x00\x00\x09"
    b"\x3a\x80\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\xab\xcd\x00\x00"
    b"\x00\x00\x00\x00\x00\x00"
)

# ICMPv6 NA with TLLA, non-DAD (target is the sender's address).
_FRAME_RX__NA_WITH_TLLA: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x88\x00\xa8\xbb\x40\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x91\x02\x01"
    b"\x02\x00\x00\x00\x00\x91"
)

# ICMPv6 NA without TLLA, non-DAD.
_FRAME_RX__NA_WITHOUT_TLLA: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x18\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x88\x00\xad\x55\x40\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x91"
)

# ICMPv6 unknown type 200.
_FRAME_RX__UNKNOWN_TYPE: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x04\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\xc8\x00\xdb\xb4"
)

# ICMPv6 truncated (4 bytes only, below the 8-byte parser minimum).
_FRAME_RX__TRUNCATED: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x04\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x80\x00\x00\x00"
)

# ICMPv6 Router Solicitation to the all-routers multicast.
_FRAME_RX__ROUTER_SOLICITATION: bytes = (
    b"\x33\x33\x00\x00\x00\x02\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x08\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x02\x85\x00\x7c\xa6\x00\x00\x00\x00"
)

# ICMPv6 MLDv2 Report (0 records) to the MLDv2-routers multicast.
_FRAME_RX__MLD2_REPORT: bytes = (
    b"\x33\x33\x00\x00\x00\x16\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x08\x3a\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x16\x8f\x00\x72\x92\x00\x00\x00\x00"
)

# ICMPv6 NA with target = stack DAD candidate (2001:db8:0:1::5).
_FRAME_RX__NA_DAD_MATCH: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
    b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x07\x88\x00\xa9\x47\x40\x00\x00\x00\x20\x01"
    b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x05\x02\x01"
    b"\x02\x00\x00\x00\x00\x91"
)


# Repeated counters block for outbound NA emission. Used by every
# NS-success scenario below.
_NA_TX_STATS: dict[str, Any] = {
    "icmp6__pre_assemble": 1,
    "icmp6__nd__neighbor_advertisement__send": 1,
    "ip6__pre_assemble": 1,
    "ip6__mtu_ok__send": 1,
    "ethernet__pre_assemble": 1,
    "ethernet__src_unspec__fill": 1,
    "ethernet__dst_unspec__ip6_lookup": 1,
    "ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send": 1,
}


class TestIcmp6Rx__EchoRequest(IcmpTestCase):
    """
    The IPv6 Echo Request → Echo Reply roundtrip.
    """

    def test__icmp6__rx__echo_request__emits_one_reply(self) -> None:
        """
        Ensure an inbound Echo Request produces exactly one TX frame.

        Reference: RFC 4443 §4.1 (Echo Request).
        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Expected one TX frame for Echo Request, got {len(frames_tx)}: {frames_tx!r}",
        )

    def test__icmp6__rx__echo_request__reply_message_fields(self) -> None:
        """
        Ensure the Echo Reply mirrors the request's id, seq and data
        and uses ICMPv6 type=129 / code=0.

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)
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
        )

    def test__icmp6__rx__echo_request__reply_ip_layer(self) -> None:
        """
        Ensure the Echo Reply IPv6 src/dst swap and hop limit is set
        to 255 as required for outbound replies.

        Reference: RFC 4443 §2.4 (Hop Limit on outbound).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self._assert_icmp6_message(
            probe,
            ip_src=Ip6Address("2001:db8:0:1::7"),
            ip_dst=Ip6Address("2001:db8:0:1::91"),
            ip_hop=255,
            ip_dscp=0,
            ip_ecn=0,
            ip_flow=0,
        )

    def test__icmp6__rx__echo_request__packet_stats_rx(self) -> None:
        """
        Ensure the inbound Echo Request bumps exactly the RX counters
        the legacy byte-equality matrix used to pin.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__echo_request__respond_echo_reply=1,
        )

    def test__icmp6__rx__echo_request__packet_stats_tx(self) -> None:
        """
        Ensure the outbound Echo Reply bumps exactly the TX counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)

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


@parameterized_class(
    [
        {
            "_description": "NS to a unicast destination, with SLLA (ND cache update)",
            "_FRAME_RX": _FRAME_RX__NS_UNICAST_WITH_SLLA,
            "_NS_RX_STATS": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_unicast": 1,
                "ip6__pre_parse": 1,
                "ip6__dst_unicast": 1,
                "icmp6__pre_parse": 1,
                "icmp6__nd_neighbor_solicitation": 1,
                "icmp6__nd_neighbor_solicitation__update_nd_cache": 1,
                "icmp6__nd_neighbor_solicitation__target_stack__respond": 1,
            },
        },
        {
            "_description": "NS to the solicited-node multicast, no SLLA (no cache update)",
            "_FRAME_RX": _FRAME_RX__NS_MULTICAST_NO_SLLA,
            "_NS_RX_STATS": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_multicast": 1,
                "ip6__pre_parse": 1,
                "ip6__dst_multicast": 1,
                "icmp6__pre_parse": 1,
                "icmp6__nd_neighbor_solicitation": 1,
                "icmp6__nd_neighbor_solicitation__target_stack__respond": 1,
            },
        },
        {
            "_description": "NS to the solicited-node multicast, with SLLA (ND cache update)",
            "_FRAME_RX": _FRAME_RX__NS_MULTICAST_WITH_SLLA,
            "_NS_RX_STATS": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_multicast": 1,
                "ip6__pre_parse": 1,
                "ip6__dst_multicast": 1,
                "icmp6__pre_parse": 1,
                "icmp6__nd_neighbor_solicitation": 1,
                "icmp6__nd_neighbor_solicitation__update_nd_cache": 1,
                "icmp6__nd_neighbor_solicitation__target_stack__respond": 1,
            },
        },
    ]
)
class TestIcmp6Rx__NsRespondsWithNa(IcmpTestCase):
    """
    The inbound-NS-triggers-NA scenarios (unicast / multicast,
    with / without SLLA).
    """

    _description: str
    _FRAME_RX: bytes
    _NS_RX_STATS: dict[str, Any]

    def test__icmp6__rx__ns__emits_one_na(self) -> None:
        """
        Ensure the NS emits exactly one outbound NA frame.

        Reference: RFC 4861 §7.2.4 (Sending Solicited Advertisements).
        """

        frames_tx = self._drive_rx(frame=self._FRAME_RX)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Expected one outbound NA, got {len(frames_tx)}: {frames_tx!r}",
        )

    def test__icmp6__rx__ns__na_message_fields(self) -> None:
        """
        Ensure the outbound NA carries ICMPv6 type=136 / code=0 and
        the requested target address (the stack's IPv6 address).

        Reference: RFC 4861 §4.4 (Neighbor Advertisement Message Format).
        """

        frames_tx = self._drive_rx(frame=self._FRAME_RX)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT),
            code=0,
            id=None,
            seq=None,
            target=Ip6Address("2001:db8:0:1::7"),
        )

    def test__icmp6__rx__ns__packet_stats_rx(self) -> None:
        """
        Ensure the NS bumps exactly the RX counters the legacy
        byte-equality matrix pinned for this scenario variant.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=self._FRAME_RX)

        self._assert_packet_stats_rx(**self._NS_RX_STATS)

    def test__icmp6__rx__ns__packet_stats_tx(self) -> None:
        """
        Ensure the outbound NA bumps exactly the canonical NA TX
        counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=self._FRAME_RX)

        self._assert_packet_stats_tx(**_NA_TX_STATS)


class TestIcmp6Rx__NsDad(IcmpTestCase):
    """
    Inbound DAD probe (NS with src=:: and target=stack address).
    The handler responds with a gratuitous NA defending the address.
    """

    def test__icmp6__rx__ns_dad__emits_one_na(self) -> None:
        """
        Ensure the DAD probe triggers exactly one outbound NA.

        Reference: RFC 4861 §7.2.5 (DAD response).
        Reference: RFC 4862 §5.4 (Duplicate Address Detection).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__NS_DAD)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Expected one outbound DAD NA, got {len(frames_tx)}: {frames_tx!r}",
        )

    def test__icmp6__rx__ns_dad__na_destination_is_all_nodes(self) -> None:
        """
        Ensure the DAD-response NA targets the all-nodes multicast
        (ff02::1) since the original NS source was unspecified.

        Reference: RFC 4861 §7.2.4 (NA destination on unsolicited path).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__NS_DAD)
        probe = self._parse_tx_icmp6(frames_tx[0])

        self._assert_icmp6_message(
            probe,
            ip_dst=Ip6Address("ff02::1"),
        )

    def test__icmp6__rx__ns_dad__packet_stats_rx(self) -> None:
        """
        Ensure the DAD probe bumps both the generic NS counter and
        the DAD-specific counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NS_DAD)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_multicast=1,
            ip6__pre_parse=1,
            ip6__dst_multicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_neighbor_solicitation=1,
            icmp6__nd_neighbor_solicitation__dad=1,
            icmp6__nd_neighbor_solicitation__target_stack__respond=1,
        )

    def test__icmp6__rx__ns_dad__packet_stats_tx(self) -> None:
        """
        Ensure the DAD-response NA bumps the multicast send counter
        (rather than the locnet ND-cache-hit counter), since the
        all-nodes destination is multicast.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NS_DAD)

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_advertisement__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Rx__EchoReplyNoSocket(IcmpTestCase):
    """
    Inbound Echo Reply with no matching RAW socket.
    """

    def test__icmp6__rx__echo_reply_no_socket__no_tx(self) -> None:
        """
        Ensure an Echo Reply with no matching RAW socket produces no
        TX frames.

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REPLY_NO_SOCKET)

        self._assert_no_tx()

    def test__icmp6__rx__echo_reply_no_socket__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__echo_reply' is bumped on the no-socket path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REPLY_NO_SOCKET)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__echo_reply=1,
        )

    def test__icmp6__rx__echo_reply_no_socket__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the no-socket Echo Reply
        path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REPLY_NO_SOCKET)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__DestUnreachableNoSocket(IcmpTestCase):
    """
    Inbound Destination Unreachable with valid embedded IPv6+UDP
    that does not match any UDP socket.
    """

    def test__icmp6__rx__dst_unreach_no_socket__no_tx(self) -> None:
        """
        Ensure a Destination Unreachable that fails to find a UDP
        socket produces no TX frames.

        Reference: RFC 4443 §3.1 (Destination Unreachable Message).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_NO_SOCKET)

        self._assert_no_tx()

    def test__icmp6__rx__dst_unreach_no_socket__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__destination_unreachable' is incremented even
        when no UDP socket matches the embedded metadata.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_NO_SOCKET)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__destination_unreachable=1,
        )

    def test__icmp6__rx__dst_unreach_no_socket__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the unmatched Destination
        Unreachable path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_NO_SOCKET)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__DestUnreachableBadEmbedded(IcmpTestCase):
    """
    Inbound Destination Unreachable whose embedded data fails the
    IPv6 version integrity check inside the demux.
    """

    def test__icmp6__rx__dst_unreach_bad_embedded__no_tx(self) -> None:
        """
        Ensure a Destination Unreachable whose embedded data is not
        a valid IPv6 packet produces no TX frames.

        Reference: RFC 4443 §3.1 (Destination Unreachable Message).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_BAD_EMBEDDED)

        self._assert_no_tx()

    def test__icmp6__rx__dst_unreach_bad_embedded__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__destination_unreachable' is incremented even
        when the embedded data is malformed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_BAD_EMBEDDED)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__destination_unreachable=1,
        )

    def test__icmp6__rx__dst_unreach_bad_embedded__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the malformed-embedded
        Destination Unreachable path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_BAD_EMBEDDED)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__RouterAdvertisement(IcmpTestCase):
    """
    Inbound Router Advertisement carrying a Prefix Information option.
    """

    def test__icmp6__rx__router_advertisement__no_tx(self) -> None:
        """
        Ensure an inbound RA produces no TX frames — the handler is
        passive and only updates the prefix list.

        Reference: RFC 4861 §6.3.4 (Processing Received Router Advertisements).
        """

        self._drive_rx(frame=_FRAME_RX__ROUTER_ADVERTISEMENT)

        self._assert_no_tx()

    def test__icmp6__rx__router_advertisement__packet_stats_rx(self) -> None:
        """
        Ensure the RA handler bumps 'icmp6__nd_router_advertisement'
        and — because the fixture frame carries a non-zero
        router_lifetime — also the §11 default-router-list
        'update_router' counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 4861 §6.3.4 (RA processing — default-router list).
        """

        self._drive_rx(frame=_FRAME_RX__ROUTER_ADVERTISEMENT)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_router_advertisement=1,
            icmp6__nd_router_advertisement__update_router=1,
            icmp6__nd_router_advertisement__pi__update_address=1,
            icmp6__nd_router_advertisement__cur_hop_limit__update=1,
        )

    def test__icmp6__rx__router_advertisement__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped by the RA handler.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ROUTER_ADVERTISEMENT)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__NaWithTlla(IcmpTestCase):
    """
    Inbound NA carrying a TLLA option, non-DAD: triggers an ND cache
    update.
    """

    def test__icmp6__rx__na_with_tlla__no_tx(self) -> None:
        """
        Ensure an NA with TLLA produces no TX frames.

        Reference: RFC 4861 §7.2.5 (Receiving NAs).
        """

        self._drive_rx(frame=_FRAME_RX__NA_WITH_TLLA)

        self._assert_no_tx()

    def test__icmp6__rx__na_with_tlla__packet_stats_rx(self) -> None:
        """
        Ensure the NA bumps both the generic counter and the
        cache-update counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_WITH_TLLA)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_neighbor_advertisement=1,
            icmp6__nd_neighbor_advertisement__update_nd_cache=1,
        )

    def test__icmp6__rx__na_with_tlla__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the NA-with-TLLA path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_WITH_TLLA)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__NaWithoutTlla(IcmpTestCase):
    """
    Inbound NA without TLLA option, non-DAD: no cache update.
    """

    def test__icmp6__rx__na_without_tlla__no_tx(self) -> None:
        """
        Ensure an NA without TLLA produces no TX frames.

        Reference: RFC 4861 §7.2.5 (Receiving NAs).
        """

        self._drive_rx(frame=_FRAME_RX__NA_WITHOUT_TLLA)

        self._assert_no_tx()

    def test__icmp6__rx__na_without_tlla__packet_stats_rx(self) -> None:
        """
        Ensure the NA bumps only the generic counter — no cache
        update without a TLLA.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_WITHOUT_TLLA)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_neighbor_advertisement=1,
        )

    def test__icmp6__rx__na_without_tlla__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the NA-without-TLLA path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_WITHOUT_TLLA)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__UnknownType(IcmpTestCase):
    """
    Inbound ICMPv6 frame with unhandled type 200.
    """

    def test__icmp6__rx__unknown_type__no_tx(self) -> None:
        """
        Ensure an unknown ICMPv6 type produces no TX frames.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__UNKNOWN_TYPE)

        self._assert_no_tx()

    def test__icmp6__rx__unknown_type__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__unknown' is bumped on the unhandled-type path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__UNKNOWN_TYPE)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__unknown=1,
        )

    def test__icmp6__rx__unknown_type__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the unknown-type path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__UNKNOWN_TYPE)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__Truncated(IcmpTestCase):
    """
    Inbound ICMPv6 message truncated below the parser's minimum.
    """

    def test__icmp6__rx__truncated__no_tx(self) -> None:
        """
        Ensure a truncated ICMPv6 frame produces no TX — the parser
        raises before any message-type dispatch runs.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__TRUNCATED)

        self._assert_no_tx()

    def test__icmp6__rx__truncated__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__failed_parse__drop' is bumped and message
        dispatch is skipped.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__TRUNCATED)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__failed_parse__drop=1,
        )

    def test__icmp6__rx__truncated__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the truncated-frame path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__TRUNCATED)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__RouterSolicitation(IcmpTestCase):
    """
    Inbound Router Solicitation to the all-routers multicast.
    Requires joining the all-routers IPv6 + Ethernet multicast groups.
    """

    _ALL_ROUTERS__IP6 = Ip6Address("ff02::2")
    _ALL_ROUTERS__MAC = MacAddress("33:33:00:00:00:02")

    @override
    def setUp(self) -> None:
        """
        Join the all-routers IPv6 and Ethernet multicast groups so the
        RS frame passes the RX classifier.
        """

        super().setUp()
        self._packet_handler._mac_multicast.append(self._ALL_ROUTERS__MAC)
        self._packet_handler._ip6_multicast.append(self._ALL_ROUTERS__IP6)

    def test__icmp6__rx__router_solicitation__no_tx(self) -> None:
        """
        Ensure an inbound RS produces no TX frames on a host stack —
        the handler is passive on the RS dispatch arm.

        Reference: RFC 4861 §6.1.1 (Validation of Router Solicitations).
        """

        self._drive_rx(frame=_FRAME_RX__ROUTER_SOLICITATION)

        self._assert_no_tx()

    def test__icmp6__rx__router_solicitation__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__nd_router_solicitation' is bumped for a valid
        inbound RS.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ROUTER_SOLICITATION)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_multicast=1,
            ip6__pre_parse=1,
            ip6__dst_multicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_router_solicitation=1,
        )

    def test__icmp6__rx__router_solicitation__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the RS handler path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ROUTER_SOLICITATION)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__Mld2Report(IcmpTestCase):
    """
    Inbound MLDv2 Report to the MLDv2-routers multicast (ff02::16).
    """

    _MLD2_ROUTERS__IP6 = Ip6Address("ff02::16")
    _MLD2_ROUTERS__MAC = MacAddress("33:33:00:00:00:16")

    @override
    def setUp(self) -> None:
        """
        Join the MLDv2-routers IPv6 and Ethernet multicast groups.
        """

        super().setUp()
        self._packet_handler._mac_multicast.append(self._MLD2_ROUTERS__MAC)
        self._packet_handler._ip6_multicast.append(self._MLD2_ROUTERS__IP6)

    def test__icmp6__rx__mld2_report__no_tx(self) -> None:
        """
        Ensure an inbound MLDv2 Report produces no TX frames.

        Reference: RFC 3810 §5.2 (Reception of MLDv2 reports).
        """

        self._drive_rx(frame=_FRAME_RX__MLD2_REPORT)

        self._assert_no_tx()

    def test__icmp6__rx__mld2_report__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp6__mld2_report' is bumped for a valid inbound
        MLDv2 Report.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__MLD2_REPORT)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_multicast=1,
            ip6__pre_parse=1,
            ip6__dst_multicast=1,
            icmp6__pre_parse=1,
            icmp6__mld2_report=1,
        )

    def test__icmp6__rx__mld2_report__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the MLDv2 Report path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__MLD2_REPORT)

        self._assert_packet_stats_tx()


class TestIcmp6Rx__NaDadMatch(IcmpTestCase):
    """
    Inbound NA whose target matches the DAD candidate IP currently
    being probed. The handler must capture the peer's TLLA, release
    the DAD semaphore, and bump the DAD-specific stat.
    """

    _CANDIDATE__IP6 = Ip6Address("2001:db8:0:1::5")

    @override
    def setUp(self) -> None:
        """
        Install a DAD candidate on the packet handler so the NA target
        matches and the DAD branch fires.
        """

        super().setUp()
        self._packet_handler._icmp6_nd_dad__registry.install(self._CANDIDATE__IP6)

    def test__icmp6__rx__na_dad_match__no_tx(self) -> None:
        """
        Ensure a DAD-matching NA produces no TX frames.

        Reference: RFC 4862 §5.4.2 (Sending Neighbor Solicitation Messages).
        """

        self._drive_rx(frame=_FRAME_RX__NA_DAD_MATCH)

        self._assert_no_tx()

    def test__icmp6__rx__na_dad_match__bumps_run_dad_stat(self) -> None:
        """
        Ensure the DAD-matching NA bumps 'icmp6__nd_neighbor_advertisement'
        and 'icmp6__nd_neighbor_advertisement__run_dad'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_DAD_MATCH)

        stats = self._packet_handler.packet_stats_rx
        self.assertEqual(
            stats.icmp6__nd_neighbor_advertisement,
            1,
            msg="icmp6__nd_neighbor_advertisement must be bumped for any inbound NA.",
        )
        self.assertEqual(
            stats.icmp6__nd_neighbor_advertisement__run_dad,
            1,
            msg="NA matching the DAD candidate must bump '__run_dad'.",
        )

    def test__icmp6__rx__na_dad_match__captures_tlla(self) -> None:
        """
        Ensure the handler captures the peer TLLA from the NA into
        the per-address slot's peer-info field.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_DAD_MATCH)

        self.assertEqual(
            self._packet_handler._icmp6_nd_dad__registry.peer_info(self._CANDIDATE__IP6),
            MacAddress("02:00:00:00:00:91"),
            msg="Handler must capture the peer TLLA into the per-address slot.",
        )

    def test__icmp6__rx__na_dad_match__releases_event(self) -> None:
        """
        Ensure the handler sets the per-address Event in the
        DAD slot registry so the DAD waiter wakes up.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__NA_DAD_MATCH)

        self.assertTrue(
            self._packet_handler._icmp6_nd_dad__registry.has_signal(self._CANDIDATE__IP6),
            msg="Handler must set the per-address DAD Event for matching NAs.",
        )
