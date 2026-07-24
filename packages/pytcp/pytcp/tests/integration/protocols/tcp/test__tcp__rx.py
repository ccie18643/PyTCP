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
This module contains integration tests for the TCP RX packet-handler path.

pytcp/tests/integration/protocols/tcp/test__tcp__rx.py

ver 3.0.9
"""

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.parameterized import parameterized_class
from pytcp.tests.lib.tcp_testcase import TcpTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/TCP - SYN to closed port",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0001
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646e
                #   Source IP       : 10.0.1.91
                #   Destination IP  : 10.0.1.7
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x000004d2
                #   Acknowledgement : 0x00000000
                #   Flags           : SYN
                #   Window          : 0x2000
                #   Checksum        : 0x68f7
                #
                # Summary: Inbound TCP SYN from host 10.0.1.91:1000 targeting closed
                #          port 2000 on the stack host 10.0.1.7.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x28\x00\x01\x00\x00\x40\x06\x64\x6e\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\xe8\x07\xd0\x00\x00\x04\xd2\x00\x00\x00\x00\x50\x02"
                b"\x20\x00\x68\xf7\x00\x00",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 54 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0028 (40 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 6 (TCP)
                #   Header Checksum : 0x646f
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # TCP
                #   Source Port     : 2000
                #   Destination Port: 1000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x000004d3
                #   Flags           : RST, ACK
                #   Window          : 0x0000
                #   Checksum        : 0x88e4
                #
                # Summary: TCP RST+ACK sent from 10.0.1.7:2000 to refuse the SYN from
                #          10.0.1.91:1000 against the closed port.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x40\x00\x40\x06\x24\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x07\xd0\x03\xe8\x00\x00\x00\x00\x00\x00\x04\xd3\x50\x14"
                b"\x00\x00\x88\xe4\x00\x00",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                tcp__pre_parse=1,
                tcp__no_socket_match__respond_rst=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/TCP - SYN to closed port",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : 2001:db8:0:1::7
                #
                # TCP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Sequence Number : 0x000004d2
                #   Acknowledgement : 0x00000000
                #   Flags           : SYN
                #   Window          : 0x2000
                #   Checksum        : 0x234d
                #
                # Summary: IPv6 TCP SYN from 2001:db8:0:1::91:1000 attempting to open
                #          closed port 2000 on 2001:db8:0:1::7.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x03\xe8\x07\xd0\x00\x00\x04\xd2\x00\x00"
                b"\x00\x00\x50\x02\x20\x00\x23\x4d\x00\x00",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 74 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0014 (20 bytes)
                #   Next Header    : 6 (TCP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # TCP
                #   Source Port     : 2000
                #   Destination Port: 1000
                #   Sequence Number : 0x00000000
                #   Acknowledgement : 0x000004d3
                #   Flags           : RST, ACK
                #   Window          : 0x0000
                #   Checksum        : 0x433a
                #
                # Summary: TCP RST+ACK issued by 2001:db8:0:1::7:2000 rejecting the SYN
                #          from 2001:db8:0:1::91:1000 against the closed service.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x07\xd0\x03\xe8\x00\x00\x00\x00\x00\x00"
                b"\x04\xd3\x50\x14\x00\x00\x43\x3a\x00\x00",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                tcp__pre_parse=1,
                tcp__no_socket_match__respond_rst=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/TCP - malformed (corrupted checksum), failed parse drop",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=TCP
                # TCP: SYN with checksum corrupted to 0xffff (intentionally invalid)
                #
                # Summary: TCP packet with bad checksum triggers TcpParser to raise
                #          'TcpIntegrityError'; bumps 'tcp__failed_parse__drop' and
                #          skips socket dispatch entirely.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x28\x00\x01\x00\x00\x40\x06\x64\x6e\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\xe8\x07\xd0\x00\x00\x04\xd2\x00\x00\x00\x00\x50\x02"
                b"\x20\x00\xff\xff\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                tcp__pre_parse=1,
                tcp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv4/TCP - RST to closed port, silently drop (no RST in response)",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x0800
                # IPv4: src=10.0.1.91, dst=10.0.1.7, proto=TCP
                # TCP: sport=1000, dport=2000 (closed), flags=RST+ACK, seq=0x4d2
                #
                # Summary: TCP RST targeting a closed port. The handler must NOT respond
                #          with another RST (RFC 793 — never RST a RST). Bumps
                #          'tcp__no_socket_match__rst__drop' and stays silent.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x28\x00\x01\x00\x00\x40\x06\x64\x6e\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\xe8\x07\xd0\x00\x00\x04\xd2\x00\x00\x00\x00\x50\x14"
                b"\x00\x00\x88\xe5\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                tcp__pre_parse=1,
                tcp__no_socket_match__rst__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestTcpRx(TcpTestCase):
    """
    The TCP RX packet-handler path tests.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__tcp__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received TCP
        frames as expected for each parametrized case.

        Reference: RFC 9293 §3.10 (TCP RX segment processing).
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
