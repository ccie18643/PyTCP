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
This module contains integration tests for the UDP RX packet-handler path.

pytcp/tests/integration/protocols/udp/test__udp__rx.py

ver 3.0.8
"""

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.udp_testcase import UdpTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/UDP to closed port",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 77 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x003f (63 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 17 (UDP)
                #   Header Checksum : 0x644c
                #   Source IP       : 10.0.1.91
                #   Destination IP  : 10.0.1.7
                #
                # UDP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Length          : 0x002b (43 bytes)
                #   Checksum        : 0xa210
                #   Payload         : "Test UDP packet sent to closed port"
                #
                # Summary: UDP datagram from host A to an unopened port on the stack.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x3f\x00\x01\x00\x00\x40\x11\x64\x4c\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\xe8\x07\xd0\x00\x2b\xa2\x10\x54\x65\x73\x74\x20\x55"
                b"\x44\x50\x20\x70\x61\x63\x6b\x65\x74\x20\x73\x65\x6e\x74\x20\x74"
                b"\x6f\x20\x63\x6c\x6f\x73\x65\x64\x20\x70\x6f\x72\x74",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 105 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x005b (91 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 1 (ICMP)
                #   Header Checksum : 0x6441
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # ICMPv4
                #   Type / Code     : 3 / 3 (Destination Unreachable - Port Unreachable)
                #   Checksum        : 0x139b
                #   Unused          : 0x00000000
                #   Quoted IP Header: Original IPv4 header + first 8 bytes of UDP payload
                #
                # Summary: ICMPv4 Port Unreachable generated in response to the closed-port
                #          UDP probe.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x5b\x00\x00\x00\x00\x40\x01\x64\x41\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\x03\x13\x9b\x00\x00\x00\x00\x45\x00\x00\x3f\x00\x01"
                b"\x00\x00\x40\x11\x64\x4c\x0a\x00\x01\x5b\x0a\x00\x01\x07\x03\xe8"
                b"\x07\xd0\x00\x2b\xa2\x10\x54\x65\x73\x74\x20\x55\x44\x50\x20\x70"
                b"\x61\x63\x6b\x65\x74\x20\x73\x65\x6e\x74\x20\x74\x6f\x20\x63\x6c"
                b"\x6f\x73\x65\x64\x20\x70\x6f\x72\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__no_socket_match__respond_icmp4_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__destination_unreachable__port__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/UDP to closed port",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 97 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x002b (43 bytes)
                #   Next Header    : 17 (UDP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : 2001:db8:0:1::7
                #
                # UDP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Length          : 0x002b (43 bytes)
                #   Checksum        : 0x5c66
                #   Payload         : "Test UDP packet sent to closed port"
                #
                # Summary: IPv6 UDP probe targeting an unopened port.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x2b\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x03\xe8\x07\xd0\x00\x2b\x5c\x66\x54\x65"
                b"\x73\x74\x20\x55\x44\x50\x20\x70\x61\x63\x6b\x65\x74\x20\x73\x65"
                b"\x6e\x74\x20\x74\x6f\x20\x63\x6c\x6f\x73\x65\x64\x20\x70\x6f\x72"
                b"\x74",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 145 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x005b (91 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6
                #   Type / Code     : 1 / 4 (Destination Unreachable - Port Unreachable)
                #   Checksum        : 0x312b
                #   Assembled Data  : Original IPv6 header + first 8 bytes of UDP payload
                #
                # Summary: ICMPv6 Port Unreachable response quoting the triggering UDP
                #          packet.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x5b\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x01\x04\x31\x2b\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x00\x2b\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x03\xe8\x07\xd0\x00\x2b\x5c\x66\x54\x65"
                b"\x73\x74\x20\x55\x44\x50\x20\x70\x61\x63\x6b\x65\x74\x20\x73\x65"
                b"\x6e\x74\x20\x74\x6f\x20\x63\x6c\x6f\x73\x65\x64\x20\x70\x6f\x72"
                b"\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                udp__pre_parse=1,
                udp__no_socket_match__respond_icmp6_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__destination_unreachable__port__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/UDP Echo",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 53 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0027 (39 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 17 (UDP)
                #   Header Checksum : 0x6464
                #   Source IP       : 10.0.1.91
                #   Destination IP  : 10.0.1.7
                #
                # UDP
                #   Source Port     : 5527
                #   Destination Port: 7 (Echo)
                #   Length          : 0x0013 (19 bytes)
                #   Checksum        : 0x813f
                #   Payload         : "Tom Tit Tot"
                #
                # Summary: UDP echo request arriving from host A.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x27\x00\x01\x00\x00\x40\x11\x64\x64\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x15\x97\x00\x07\x00\x13\x81\x3f\x54\x6f\x6d\x20\x54\x69"
                b"\x74\x20\x54\x6f\x74",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 53 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0027 (39 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 17 (UDP)
                #   Header Checksum : 0x6465
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # UDP
                #   Source Port     : 7
                #   Destination Port: 5527
                #   Length          : 0x0013 (19 bytes)
                #   Checksum        : 0x813f
                #   Payload         : "Tom Tit Tot"
                #
                # Summary: UDP echo reply mirroring the original payload back to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x27\x00\x00\x00\x00\x40\x11\x64\x65\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x00\x07\x15\x97\x00\x13\x81\x3f\x54\x6f\x6d\x20\x54\x69"
                b"\x74\x20\x54\x6f\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__echo_native__respond_udp=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/UDP Echo",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 73 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0013 (19 bytes)
                #   Next Header    : 17 (UDP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : 2001:db8:0:1::7
                #
                # UDP
                #   Source Port     : 5527
                #   Destination Port: 7
                #   Length          : 0x0013 (19 bytes)
                #   Checksum        : 0x3b95
                #   Payload         : "Tom Tit Tot"
                #
                # Summary: IPv6 UDP echo request from host A.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x13\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x15\x97\x00\x07\x00\x13\x3b\x95\x54\x6f"
                b"\x6d\x20\x54\x69\x74\x20\x54\x6f\x74",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 73 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0013 (19 bytes)
                #   Next Header    : 17 (UDP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # UDP
                #   Source Port     : 7
                #   Destination Port: 5527
                #   Length          : 0x0013 (19 bytes)
                #   Checksum        : 0x3b95
                #   Payload         : "Tom Tit Tot"
                #
                # Summary: IPv6 UDP echo reply returning the payload to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x13\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x00\x07\x15\x97\x00\x13\x3b\x95\x54\x6f"
                b"\x6d\x20\x54\x69\x74\x20\x54\x6f\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                udp__pre_parse=1,
                udp__echo_native__respond_udp=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/UDP - malformed (corrupted checksum), failed parse drop",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=UDP
                # UDP: sport=1000, dport=2000, len=13, cksum=0xffff (intentionally invalid)
                # Payload: "hello"
                #
                # Summary: UDP packet with bad checksum triggers UdpParser to raise
                #          'UdpIntegrityError'; bumps 'udp__failed_parse__drop' and
                #          skips socket dispatch.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x21\x00\x01\x00\x00\x40\x11\x64\x6a\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\xe8\x07\xd0\x00\x0d\xff\xff\x68\x65\x6c\x6c\x6f",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv4/UDP - src IP unspecified (0.0.0.0), silently dropped",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x0800
                # IPv4: src=0.0.0.0 (unspecified), dst=10.0.1.7, proto=UDP
                # UDP: sport=68, dport=67 (DHCP-like), payload="hello", cksum=0xb074
                #
                # Summary: UDP from an unspecified source IP is silently dropped without
                #          ICMP response (avoids infinite reply loops). Bumps
                #          'udp__ip_source_unspecified'.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x21\x00\x01\x00\x00\x40\x11\x6f\xc5\x00\x00\x00\x00\x0a\x00"
                b"\x01\x07\x00\x44\x00\x43\x00\x0d\xb0\x74\x68\x65\x6c\x6c\x6f",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__ip_source_unspecified=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestUdpRx(UdpTestCase):
    """
    The UDP RX packet-handler path tests.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__udp__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received UDP
        frames as expected for each parametrized case.

        Reference: PyTCP test infrastructure (no RFC clause).
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


class TestUdpRxEchoNativeDisabled(UdpTestCase):
    """
    The UDP RX path tests for when 'stack.UDP__ECHO_NATIVE' is
    disabled. The default 'NetworkTestCase' fixture patches it to True
    (so port-7 packets are echoed), so this dedicated TestCase flips it
    off in setUp to exercise the fallthrough into the ICMP-unreachable
    branch for port-7 traffic.
    """

    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable native UDP echo.
        """

        super().setUp()
        from pytcp import stack

        stack.__dict__["UDP__ECHO_NATIVE"] = False

    def test__udp__rx__port7_echo_disabled(self) -> None:
        """
        Ensure a UDP packet to port 7 with 'UDP__ECHO_NATIVE' disabled
        falls through to the no-socket-match branch and replies with
        ICMPv4 Port Unreachable.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91
        # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=UDP
        # UDP: sport=1000, dport=7 (echo), payload="hello", cksum=0xa1b1
        #
        # Summary: With native echo off, port-7 UDP is treated as a normal closed-port
        #          packet — the handler responds with ICMPv4 Port Unreachable instead.
        frame_rx = (
            b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
            b"\x00\x21\x00\x01\x00\x00\x40\x11\x64\x6a\x0a\x00\x01\x5b\x0a\x00"
            b"\x01\x07\x03\xe8\x00\x07\x00\x0d\xa1\xb1\x68\x65\x6c\x6c\x6f"
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Echo-disabled port-7 UDP must produce exactly one ICMPv4 Unreachable response.",
        )
        # ICMPv4 Destination Unreachable, code 3 (port) sits at offset 34 (Eth+IPv4 header).
        self.assertEqual(
            self._frames_tx[0][34:36],
            b"\x03\x03",
            msg="Response must be ICMPv4 Destination Unreachable / code Port.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__no_socket_match__respond_icmp4_unreachable=1,
            ),
            msg="udp__no_socket_match__respond_icmp4_unreachable must bump (not echo).",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 source = 255.255.255.255 (limited broadcast).",
            # Ethernet II / IPv4 / UDP. IPv4 src=255.255.255.255,
            # dst=10.0.1.7. UDP cksum=0 (IPv4 accept-no-cksum) —
            # payload "hello".
            "_frame_rx": (
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x21\x00\x01\x00\x00\x40\x11\xb9\x65\xff\xff\xff\xff\x0a\x00"
                b"\x01\x07\x03\xe8\x1e\x61\x00\x0d\x00\x00\x68\x65\x6c\x6c\x6f"
            ),
            "_expected__ip_layer": "ip4",
        },
        {
            "_description": "IPv4 source = 224.0.0.1 (all-systems multicast).",
            "_frame_rx": (
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x21\x00\x01\x00\x00\x40\x11\xa4\x66\xe0\x00\x00\x01\x0a\x00"
                b"\x01\x07\x03\xe8\x1e\x61\x00\x0d\x00\x00\x68\x65\x6c\x6c\x6f"
            ),
            "_expected__ip_layer": "ip4",
        },
        {
            "_description": "IPv6 source = ff02::1 (all-nodes multicast).",
            # Ethernet II / IPv6 / UDP. IPv6 src=ff02::1,
            # dst=2001:db8:0:1::7. UDP cksum=0xffff (valid placeholder
            # — IPv6 cksum=0 would be dropped by the RFC 6935 gate; we
            # care about IP-source filtering here).
            "_frame_rx": (
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x0d\x11\x40\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x03\xe8\x1e\x61\x00\x0d\xff\xff\x68\x65"
                b"\x6c\x6c\x6f"
            ),
            "_expected__ip_layer": "ip6",
        },
    ]
)
class TestUdpRxInvalidSourceAddress(UdpTestCase):
    """
    Verify the RFC 1122 §4.1.3.6 invalid-source-address discard
    rule for UDP: a datagram arriving with a broadcast or
    multicast IP source is dropped before the UDP layer even
    sees it.

    The RFC clause permits the drop to happen at "UDP or the IP
    layer". PyTCP closes it at the IP layer — the IPv4 and IPv6
    parsers reject these sources via 'Ip4SanityError' /
    'Ip6SanityError' (`_validate_sanity` in
    `net_proto/protocols/ip4/ip4__parser.py` and the IPv6
    counterpart). UDP-layer code never sees the packet; the
    relevant counter is `ip{4,6}__failed_parse__drop`.
    """

    _description: str
    _frame_rx: bytes
    _expected__ip_layer: str

    def test__udp__rx__invalid_source_dropped_at_ip_layer(self) -> None:
        """
        Ensure inbound UDP frames with broadcast or multicast
        IP source addresses are silently dropped at the IP-
        layer parser (sanity check) and never reach the UDP
        handler. The RFC permits the drop at either UDP or
        the IP layer; PyTCP closes it at the IP layer.

        Reference: RFC 1122 §4.1.3.6 (Invalid Addresses — a UDP
        datagram with an invalid source address must be
        discarded by UDP or by the IP layer).
        """

        self._packet_handler._phrx_ethernet(PacketRx(self._frame_rx))

        # The IP layer parser sanity-rejected the source, so
        # the UDP layer never ran.
        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__pre_parse,
            0,
            msg=(
                f"UDP parser must NOT run on invalid-source packet for case: "
                f"{self._description}. The IP layer's sanity check drops it first."
            ),
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__socket_match,
            0,
            msg=f"Dropped packet must not reach socket dispatch for case: {self._description}.",
        )

        # The dedicated IP-layer failed-parse counter bumps.
        if self._expected__ip_layer == "ip4":
            self.assertEqual(
                self._packet_handler.packet_stats_rx.ip4__failed_parse__drop,
                1,
                msg=(
                    f"IPv4 parser sanity-error must bump 'ip4__failed_parse__drop' " f"for case: {self._description}."
                ),
            )
        else:
            self.assertEqual(
                self._packet_handler.packet_stats_rx.ip6__failed_parse__drop,
                1,
                msg=(
                    f"IPv6 parser sanity-error must bump 'ip6__failed_parse__drop' " f"for case: {self._description}."
                ),
            )
