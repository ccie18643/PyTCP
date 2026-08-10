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
This module contains integration tests for the UDP TX packet-handler path.

pytcp/tests/integration/protocols/udp/test__udp__tx.py

ver 3.0.10
"""

from typing import Any

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.parameterized import parameterized_class
from pytcp.tests.lib.udp_testcase import UdpTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/UDP - no payload",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "udp__sport": 1000,
                "udp__dport": 2000,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 42 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x001c (28 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 17 (UDP)
                #   Header Checksum : 0x6470
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # UDP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Length          : 0x0008 (8 bytes)
                #   Checksum        : 0xddc4
                #
                # Summary: Minimal UDP datagram with no payload transmitted from the stack
                #          host to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x1c\x00\x00\x00\x00\x40\x11\x64\x70\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x08\xdd\xc4"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
            "_description": "Ethernet/IPv4/UDP - payload",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "udp__sport": 1000,
                "udp__dport": 2000,
                "udp__payload": b"01234567890ABCDEF" * 50,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 892 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x036e (878 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 17 (UDP)
                #   Header Checksum : 0x611e
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # UDP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Length          : 0x035a (858 bytes)
                #   Checksum        : 0xf53e
                #   Payload         : 850 bytes ("01234567890ABCDEF" repeated)
                #
                # Summary: Large IPv4 UDP payload example, carrying the generated raw data
                #          towards host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x03\x6e\x00\x00\x00\x00\x40\x11\x61\x1e\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x03\x5a\xf5\x3e\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
            "_description": "Ethernet/IPv6/UDP - no payload",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "udp__sport": 1000,
                "udp__dport": 2000,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 62 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0008 (8 bytes)
                #   Next Header    : 17 (UDP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # UDP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Length          : 0x0008
                #   Checksum        : 0x981a
                #
                # Summary: Minimal IPv6 UDP datagram with no payload sent to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x08\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x08\x98\x1a"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
            "_description": "Ethernet/IPv6/UDP - payload",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "udp__sport": 1000,
                "udp__dport": 2000,
                "udp__payload": b"01234567890ABCDEF" * 50,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 912 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x035a (858 bytes)
                #   Next Header    : 17 (UDP)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # UDP
                #   Source Port     : 1000
                #   Destination Port: 2000
                #   Length          : 0x035a (858 bytes)
                #   Checksum        : 0xaf94
                #   Payload         : 850 bytes ("01234567890ABCDEF" repeated)
                #
                # Summary: IPv6 UDP payload counterpart matching the IPv4 large-payload
                #          scenario.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x03\x5a\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x03\x5a\xaf\x94\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
    ]
)
class TestUdpTx(UdpTestCase):
    """
    The UDP TX packet-handler path tests (success path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__udp__tx(self) -> None:
        """
        Ensure the Packet Handler UDP TX path produces the expected
        frames, statuses, and statistics for each parametrized case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet_handler._phtx_udp(**self._kwargs),
            self._expected__tx_status,
            msg=f"Unexpected TxStatus for case: {self._description}",
        )

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "UDP - IPv4/IPv6 version mismatch",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "udp__sport": 1000,
                "udp__dport": 2000,
            },
            "_expected__error": ValueError("Invalid IP address version combination: 10.0.1.7 -> 2001:db8:0:1::91"),
        },
        {
            "_description": "UDP - IPv6/IPv4 version mismatch",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "udp__sport": 1000,
                "udp__dport": 2000,
            },
            "_expected__error": ValueError("Invalid IP address version combination: 2001:db8:0:1::7 -> 10.0.1.91"),
        },
    ]
)
class TestUdpTxErrors(UdpTestCase):
    """
    The UDP TX packet-handler path tests (error path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__error: Exception

    def test__udp__tx__error(self) -> None:
        """
        Ensure '_phtx_udp' raises the expected exception for invalid
        IP address version combinations.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(type(self._expected__error)) as error:
            self._packet_handler._phtx_udp(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            str(self._expected__error),
            msg=f"Unexpected error message for case: {self._description}",
        )


class TestUdpTxSendUdpPacket(UdpTestCase):
    """
    Test the public 'send_udp_packet' wrapper, which forwards into
    '_phtx_udp' renaming the addressing and port kwargs.
    """

    def test__udp__tx__send_udp_packet(self) -> None:
        """
        Ensure 'send_udp_packet' renames its kwargs ('ip__local_address'
        / 'ip__remote_address' → 'ip__src' / 'ip__dst', 'udp__local_port'
        / 'udp__remote_port' → 'udp__sport' / 'udp__dport') and forwards
        to '_phtx_udp', producing the same frame and stats as a direct
        '_phtx_udp' call would.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler.send_udp_packet(
            ip__local_address=STACK__IP4_HOST.address,
            ip__remote_address=HOST_A__IP4_ADDRESS,
            udp__local_port=1000,
            udp__remote_port=2000,
            udp__payload=b"hello",
        )

        # 'send_udp_packet' is fire-and-forget (Phase 4b) — no
        # TxStatus return; assert on the emitted frame and stats.
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="send_udp_packet must emit exactly one frame for a 5-byte payload.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            msg="send_udp_packet stats must match a direct _phtx_udp call.",
        )
