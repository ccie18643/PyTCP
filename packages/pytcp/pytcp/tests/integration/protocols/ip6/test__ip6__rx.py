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
This module contains integration tests for the IPv6 RX packet-handler path.

pytcp/tests/integration/protocols/ip6/test__ip6__rx.py

ver 3.0.8
"""

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.ip6_testcase import Ip6TestCase
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv6 - dst unknown",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0 bytes
                #   Next Header    : 59 (No Next Header)
                #   Hop Limit      : 64
                #   Source IP      : 2603:9000:e307:9f09::1fa1
                #   Destination IP : 2603:9000:e307:9f09:0:ff:fe55:5555 (unknown)
                #
                # Summary: IPv6 datagram targeting an address the stack does not own; expect a drop.
                b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\x3b\x40\x26\x03\x90\x00\xe3\x07\x9f\x09\x00\x00"
                b"\x00\x00\x00\x00\x1f\xa1\x26\x03\x90\x00\xe3\x07\x9f\x09\x00\x00"
                b"\x00\xff\xfe\x55\x55\x55"
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6 - malformed IPv6 (truncated below header length), failed parse drop",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x86dd
                # IPv6: header truncated to 39 bytes (one byte short of the 40-byte minimum).
                #
                # Summary: Truncated IPv6 frame triggers Ip6Parser to raise; bumps
                #          'ip6__failed_parse__drop' and skips dst classification entirely.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\x3b\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6 - hop=0 sanity error triggers Parameter Problem (pointer=7)",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91
                # IPv6: hop=0 (byte 7) — sanity violation. Other fields valid:
                #   src=2001:db8:0:1::91, dst=2001:db8:0:1::7 (our unicast),
                #   next=99 (RAW), payload_len=0.
                #
                # Summary: Bumps 'ip6__failed_parse__drop' and emits ICMPv6
                #          Parameter Problem (Code 0, pointer=7) per RFC 1122
                #          §3.2.2.5 / RFC 4443 §3.4.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\x63\x00\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07",
            ],
            "_expected__frames_tx": [
                # Outbound ICMPv6 Parameter Problem:
                #   Ethernet: dst=peer MAC, src=our MAC, type=IPv6
                #   IPv6: src=2001:db8:0:1::7, dst=2001:db8:0:1::91, next=58 (ICMP6), hop=64
                #   ICMPv6: type=4 (Param Problem), code=0 (erroneous header field),
                #           pointer=7 (Hop Limit byte), data=embedded original 40-byte
                #           IPv6 header.
                bytes.fromhex(
                    "02000000009102000000000786dd6000000000303a4020010db8000000010000"
                    "00000000000720010db80000000100000000000000910400807500000007"
                    "600000000000630020010db8000000010000000000000091"
                    "20010db8000000010000000000000007"
                ),
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__failed_parse__drop=1,
                ip6__sanity_error__respond_icmp6_param_problem=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__parameter_problem__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": ("Ethernet/IPv6 - dst is our solicited-node multicast, unsupported next header (99), drop"),
            "_frames_rx": [
                # Ethernet II: dst=33:33:ff:00:00:07 (solicited-node MAC for ::7), src=02:00:00:00:00:91
                # IPv6: src=2001:db8:0:1::91, dst=ff02::1:ff00:7 (solicited-node multicast for ::7), next=99
                #
                # Summary: Bumps 'ip6__dst_multicast' (classifier) and
                #          'ip6__no_proto_support__drop'. The host-requirements
                #          gate suppresses the SHOULD-emit Parameter Problem
                #          (Unrecognized Next Header) response per RFC 4443
                #          §2.4(e).
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x04\x63\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                ip6__no_proto_support__drop=1,
                ip6__no_proto_support__icmp6_param_problem_suppressed=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestIp6Rx(Ip6TestCase):
    """
    The IPv6 RX packet-handler path tests.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__ip6__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received IPv6
        frames as expected for each parametrized case.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
            msg=f"Unexpected RX packet stats for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )
